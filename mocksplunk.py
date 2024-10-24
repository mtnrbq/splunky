from fastapi import FastAPI, Request, Header, HTTPException
import uvicorn
import json
from typing import Optional, Union, Dict, Any, List
from datetime import datetime
import logging
import os
from pathlib import Path
from pydantic import BaseModel

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

app = FastAPI(title="Mock Splunk HEC")

# Store received events in memory
events_store = []

# Token storage with additional metadata
class TokenInfo(BaseModel):
    token: str
    index: str
    description: str
    created_at: datetime
    last_used: Optional[datetime] = None
    disabled: bool = False

class TokenCreate(BaseModel):
    index: str
    description: str

class TokenUpdate(BaseModel):
    index: Optional[str] = None
    description: Optional[str] = None
    disabled: Optional[bool] = None

# Initialize token store with default tokens
token_store: Dict[str, TokenInfo] = {
    "your-hec-token-here": TokenInfo(
        token="your-hec-token-here",
        index="main",
        description="Default main token",
        created_at=datetime.utcnow(),
        disabled=False
    ),
    "test-token": TokenInfo(
        token="test-token",
        index="test",
        description="Test token",
        created_at=datetime.utcnow(),
        disabled=False
    )
}

# Configure dumps directory
DUMPS_DIR = Path("event_dumps")
DUMPS_DIR.mkdir(exist_ok=True)

# Token store file
TOKEN_STORE_FILE = Path("token_store.json")

def save_tokens():
    """Save tokens to persistent storage."""
    with open(TOKEN_STORE_FILE, 'w') as f:
        json.dump(
            {k: v.dict() for k, v in token_store.items()},
            f,
            indent=2,
            default=str
        )

def load_tokens():
    """Load tokens from persistent storage."""
    if TOKEN_STORE_FILE.exists():
        with open(TOKEN_STORE_FILE, 'r') as f:
            data = json.load(f)
            for k, v in data.items():
                v['created_at'] = datetime.fromisoformat(v['created_at'])
                if v['last_used']:
                    v['last_used'] = datetime.fromisoformat(v['last_used'])
                token_store[k] = TokenInfo(**v)

# Load tokens at startup
if TOKEN_STORE_FILE.exists():
    load_tokens()
else:
    save_tokens()

async def validate_token(token: str) -> bool:
    """Validate the Splunk HEC token."""
    if token not in token_store:
        return False
    token_info = token_store[token]
    if token_info.disabled:
        return False
    token_info.last_used = datetime.utcnow()
    save_tokens()
    return True

# Token Management API endpoints
@app.get("/tokens", response_model=List[TokenInfo])
async def list_tokens():
    """List all tokens."""
    return list(token_store.values())

@app.get("/tokens/{token}", response_model=TokenInfo)
async def get_token(token: str):
    """Get details for a specific token."""
    if token not in token_store:
        raise HTTPException(status_code=404, detail="Token not found")
    return token_store[token]

@app.post("/tokens", response_model=TokenInfo)
async def create_token(token_data: TokenCreate):
    """Create a new token."""
    import secrets
    
    # Generate a new token
    new_token = secrets.token_hex(16)
    while new_token in token_store:
        new_token = secrets.token_hex(16)
    
    token_info = TokenInfo(
        token=new_token,
        index=token_data.index,
        description=token_data.description,
        created_at=datetime.utcnow()
    )
    
    token_store[new_token] = token_info
    save_tokens()
    return token_info

@app.patch("/tokens/{token}", response_model=TokenInfo)
async def update_token(token: str, token_data: TokenUpdate):
    """Update an existing token."""
    if token not in token_store:
        raise HTTPException(status_code=404, detail="Token not found")
    
    token_info = token_store[token]
    
    if token_data.index is not None:
        token_info.index = token_data.index
    if token_data.description is not None:
        token_info.description = token_data.description
    if token_data.disabled is not None:
        token_info.disabled = token_data.disabled
    
    save_tokens()
    return token_info

@app.delete("/tokens/{token}")
async def delete_token(token: str):
    """Delete a token."""
    if token not in token_store:
        raise HTTPException(status_code=404, detail="Token not found")
    
    del token_store[token]
    save_tokens()
    return {"message": "Token deleted successfully"}

@app.post("/services/collector")
async def receive_event(
    request: Request,
    authorization: Optional[str] = Header(None),
    splunk_token: Optional[str] = Header(None, alias="X-Splunk-Token")
):
    """
    Mock Splunk HEC endpoint that receives and stores events.
    Supports both authorization header and X-Splunk-Token header.
    """
    # Validate token
    token = None
    if authorization and authorization.startswith("Splunk "):
        token = authorization.split(" ")[1]
    elif splunk_token:
        token = splunk_token
    
    if not token or not await validate_token(token):
        raise HTTPException(
            status_code=401,
            detail="Invalid token"
        )

    # Get request body
    try:
        body = await request.body()
        content = body.decode()
        
        # Handle multiple events in NDJSON format
        events = []
        for line in content.strip().split('\n'):
            if line:
                event = json.loads(line)
                events.append(event)
                
        # Process and store events
        for event in events:
            # Add metadata
            event['_received_at'] = datetime.utcnow().isoformat()
            event['_token'] = token
            event['_index'] = token_store[token].index
            events_store.append(event)
            
            # Log the received event
            logger.info(f"Received event: {json.dumps(event)}")
        
        return {
            "text": "Success",
            "code": 0,
            "events_count": len(events)
        }
        
    except json.JSONDecodeError:
        raise HTTPException(
            status_code=400,
            detail="Invalid JSON format"
        )
    except Exception as e:
        logger.error(f"Error processing event: {str(e)}")
        raise HTTPException(
            status_code=500,
            detail=f"Internal server error: {str(e)}"
        )

@app.get("/events")
async def get_events(token: Optional[str] = None):
    """Endpoint to retrieve stored events."""
    if token:
        filtered_events = [e for e in events_store if e['_token'] == token]
        return {"events": filtered_events}
    return {"events": events_store}

@app.delete("/events")
async def clear_events():
    """Clear all stored events."""
    events_store.clear()
    return {"message": "All events cleared"}

@app.post("/events/dump")
async def dump_events(token: Optional[str] = None):
    """
    Dump events to a JSON file with timestamp in the name.
    Optionally filter by token.
    """
    timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    
    # Filter events if token provided
    events_to_dump = events_store
    if token:
        events_to_dump = [e for e in events_store if e['_token'] == token]
        filename = f"events_token_{token}_{timestamp}.json"
    else:
        filename = f"events_all_{timestamp}.json"
    
    filepath = DUMPS_DIR / filename
    
    try:
        # Create dump with metadata
        dump_data = {
            "dump_timestamp": timestamp,
            "total_events": len(events_to_dump),
            "token_filter": token,
            "events": events_to_dump
        }
        
        # Write to file with pretty printing
        with open(filepath, 'w') as f:
            json.dump(dump_data, f, indent=2)
        
        logger.info(f"Successfully dumped {len(events_to_dump)} events to {filepath}")
        
        return {
            "message": "Events dumped successfully",
            "filename": str(filepath),
            "events_count": len(events_to_dump)
        }
    
    except Exception as e:
        logger.error(f"Error dumping events: {str(e)}")
        raise HTTPException(
            status_code=500,
            detail=f"Failed to dump events: {str(e)}"
        )

@app.get("/events/dumps")
async def list_dumps():
    """List all available event dump files."""
    try:
        dumps = list(DUMPS_DIR.glob("events_*.json"))
        return {
            "dumps": [
                {
                    "filename": dump.name,
                    "created_at": datetime.fromtimestamp(dump.stat().st_mtime).isoformat(),
                    "size_bytes": dump.stat().st_size
                }
                for dump in dumps
            ]
        }
    except Exception as e:
        logger.error(f"Error listing dumps: {str(e)}")
        raise HTTPException(
            status_code=500,
            detail=f"Failed to list dumps: {str(e)}"
        )

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8088)