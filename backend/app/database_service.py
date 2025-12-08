"""
Database Service - Centralized data storage for all components
Follows DFD: All components connect to Database
"""
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from typing import Dict, Any, List, Optional
from datetime import datetime
import json
import os
from collections import defaultdict

class DatabaseEntry(BaseModel):
    """Generic database entry model"""
    collection: str = Field(..., description="Collection/table name")
    data: Dict[str, Any] = Field(..., description="Data to store")
    timestamp: datetime = Field(default_factory=datetime.now, description="Entry timestamp")

class QueryRequest(BaseModel):
    """Database query request model"""
    collection: str = Field(..., description="Collection to query")
    filters: Optional[Dict[str, Any]] = Field(None, description="Query filters")
    limit: Optional[int] = Field(100, description="Result limit")

class DatabaseService:
    """
    Database Service - Centralized data storage
    In production, this would connect to a real database (PostgreSQL, MongoDB, etc.)
    For demo purposes, uses file-based storage
    """
    
    def __init__(self):
        self.app = FastAPI(
            title="Database Service",
            description="Centralized database service for cognitive security system"
        )
        
        # Add CORS middleware
        self.app.add_middleware(
            CORSMiddleware,
            allow_origins=["http://localhost:3000", "http://127.0.0.1:3000"],
            allow_credentials=True,
            allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
            allow_headers=["*"],
        )
        
        self.data_dir = "data/database"
        self.collections: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
        self._ensure_data_directory()
        self._load_existing_data()
        self.setup_routes()
    
    def _ensure_data_directory(self):
        """Ensure data directory exists"""
        os.makedirs(self.data_dir, exist_ok=True)
    
    def _load_existing_data(self):
        """Load existing data from files"""
        try:
            for filename in os.listdir(self.data_dir):
                if filename.endswith(".json"):
                    collection_name = filename[:-5]  # Remove .json extension
                    filepath = os.path.join(self.data_dir, filename)
                    with open(filepath, 'r') as f:
                        self.collections[collection_name] = json.load(f)
        except Exception as e:
            print(f"Error loading existing data: {e}")
    
    def _save_collection(self, collection_name: str):
        """Save collection to file"""
        try:
            filepath = os.path.join(self.data_dir, f"{collection_name}.json")
            with open(filepath, 'w') as f:
                json.dump(self.collections[collection_name], f, indent=2, default=str)
        except Exception as e:
            print(f"Error saving collection {collection_name}: {e}")
    
    def setup_routes(self):
        """Setup database service endpoints"""
        
        @self.app.get("/health")
        async def health_check():
            """Database service health check"""
            return {
                "status": "Database Service Operational",
                "collections": list(self.collections.keys()),
                "total_entries": sum(len(entries) for entries in self.collections.values())
            }
        
        @self.app.post("/store")
        async def store_data(entry: DatabaseEntry):
            """
            Store data in specified collection
            Follows DFD: All components → Database
            """
            try:
                # Add entry to collection
                collection_entry = {
                    "id": str(len(self.collections[entry.collection]) + 1),
                    "timestamp": entry.timestamp.isoformat(),
                    "data": entry.data
                }
                self.collections[entry.collection].append(collection_entry)
                
                # Save to file
                self._save_collection(entry.collection)
                
                return {
                    "status": "success",
                    "collection": entry.collection,
                    "entry_id": collection_entry["id"],
                    "timestamp": collection_entry["timestamp"]
                }
                
            except Exception as e:
                raise HTTPException(
                    status_code=500,
                    detail=f"Failed to store data: {str(e)}"
                )
        
        @self.app.post("/query")
        async def query_data(query: QueryRequest):
            """Query data from collection"""
            try:
                collection = self.collections.get(query.collection, [])
                
                # Apply filters if provided
                if query.filters:
                    filtered_results = []
                    for entry in collection:
                        match = True
                        for key, value in query.filters.items():
                            if key not in entry["data"] or entry["data"][key] != value:
                                match = False
                                break
                        if match:
                            filtered_results.append(entry)
                    collection = filtered_results
                
                # Apply limit
                if query.limit:
                    collection = collection[:query.limit]
                
                return {
                    "collection": query.collection,
                    "results": collection,
                    "total_count": len(collection)
                }
                
            except Exception as e:
                raise HTTPException(
                    status_code=500,
                    detail=f"Query failed: {str(e)}"
                )
        
        @self.app.get("/collections")
        async def list_collections():
            """List all collections and their stats"""
            stats = {}
            for name, entries in self.collections.items():
                stats[name] = {
                    "entry_count": len(entries),
                    "latest_entry": entries[-1]["timestamp"] if entries else None
                }
            return {
                "collections": stats,
                "total_collections": len(self.collections)
            }
        
        @self.app.get("/collection/{collection_name}")
        async def get_collection(collection_name: str, limit: int = 100):
            """Get all entries from a collection"""
            if collection_name not in self.collections:
                raise HTTPException(
                    status_code=404,
                    detail=f"Collection {collection_name} not found"
                )
            
            entries = self.collections[collection_name][-limit:]  # Get latest entries
            return {
                "collection": collection_name,
                "entries": entries,
                "total_count": len(self.collections[collection_name])
            }
        
        @self.app.delete("/collection/{collection_name}")
        async def clear_collection(collection_name: str):
            """Clear all entries from a collection (admin only)"""
            if collection_name not in self.collections:
                raise HTTPException(
                    status_code=404,
                    detail=f"Collection {collection_name} not found"
                )
            
            self.collections[collection_name] = []
            self._save_collection(collection_name)
            
            return {
                "status": "success",
                "message": f"Collection {collection_name} cleared"
            }
        
        @self.app.get("/stats")
        async def get_database_stats():
            """Get comprehensive database statistics"""
            stats = {
                "total_collections": len(self.collections),
                "total_entries": sum(len(entries) for entries in self.collections.values()),
                "collection_details": {}
            }
            
            for name, entries in self.collections.items():
                stats["collection_details"][name] = {
                    "entry_count": len(entries),
                    "size_bytes": len(json.dumps(entries)),
                    "latest_entry": entries[-1]["timestamp"] if entries else None
                }
            
            return stats
    
    def get_app(self):
        """Get FastAPI app instance"""
        return self.app

# Initialize Database Service
database_service = DatabaseService()
app = database_service.get_app()
