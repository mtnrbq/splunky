# https://claude.site/artifacts/dfa89957-d92f-4a2f-ae73-64cbc8df1ce7

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

class TokenInfo(BaseModel):
    token: str
    index: str
    description: str
    created_at: datetime
    last_used: Optional[datetime] = None
    disabled: bool = False

# Token storage with metadata
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

def parse_concatenated_json(content: str) -> List[dict]:
    """
    Parse concatenated JSON objects that don't have newlines between them.
    Example input: '{"event":"1"}{"event":"2"}{"event":"3"}'
    """
    if not content.strip():
        return []
    
    # If the content is a single valid JSON object, return it as a list
    try:
        return [json.loads(content)]
    except json.JSONDecodeError:
        pass
    
    # Split concatenated objects and reconstruct
    parts = content.split("}{")
    
    if len(parts) == 1:
        # No concatenation found, might be invalid JSON
        raise json.JSONDecodeError("Invalid JSON format", content, 0)
    
    result = []
    for i, part in enumerate(parts):
        # Reconstruct the JSON object by adding back the braces
        if i == 0:
            # First part needs closing brace
            json_str = part + "}"
        elif i == len(parts) - 1:
            # Last part needs opening brace
            json_str = "{" + part
        else:
            # Middle parts need both braces
            json_str = "{" + part + "}"
        
        try:
            obj = json.loads(json_str)
            result.append(obj)
        except json.JSONDecodeError as e:
            logger.error(f"Error parsing JSON part {i}: {json_str}")
            raise json.JSONDecodeError(
                f"Invalid JSON in part {i}", json_str, e.pos
            )
    
    return result

async def validate_token(token: str) -> bool:
    """Validate the Splunk HEC token."""
    if token not in token_store:
        return False
    token_info = token_store[token]
    if token_info.disabled:
        return False
    token_info.last_used = datetime.utcnow()
    return True

@app.post("/services/collector")
async def receive_event(
    request: Request,
    authorization: Optional[str] = Header(None),
    splunk_token: Optional[str] = Header(None, alias="X-Splunk-Token")
):
    """
    Mock Splunk HEC endpoint that receives and stores events.
    Supports both authorization header and X-Splunk-Token header.
    Handles concatenated JSON objects without newlines.
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
        
        # Parse concatenated JSON objects
        events = parse_concatenated_json(content)
        
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
        
    except json.JSONDecodeError as e:
        logger.error(f"JSON parsing error: {str(e)}")
        raise HTTPException(
            status_code=400,
            detail=f"Invalid JSON format: {str(e)}"
        )
    except Exception as e:
        logger.error(f"Error processing event: {str(e)}")
        raise HTTPException(
            status_code=500,
            detail=f"Internal server error: {str(e)}"
        )

# ... rest of the code remains the same (token and event management endpoints) ...

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8088)