import chromadb
from chromadb.config import Settings
from pathlib import Path
from typing import List, Dict
import json

class RAGStore:
    def __init__(self, persist_dir: str = "./.semgrepai/db"):
        self.persist_dir = Path(persist_dir)
        self.persist_dir.mkdir(parents=True, exist_ok=True)
        
        self.client = chromadb.Client(Settings(
            persist_directory=str(self.persist_dir),
            anonymized_telemetry=False
        ))
        
        self.findings_collection = self.client.get_or_create_collection(
            name="findings",
            metadata={"hnsw:space": "cosine"}
        )

    def store_findings(self, findings: List[Dict]):
        """Store findings in the vector database."""
        documents = []
        metadatas = []
        ids = []
        
        for i, finding in enumerate(findings):
            # Create searchable document from finding
            doc = f"""
            Rule: {finding['rule_id']}
            Severity: {finding['severity']}
            Message: {finding['message']}
            Code: {finding['code']}
            Path: {finding['path']}
            Line: {finding['line']}
            """
            
            # Store complete finding data in metadata
            metadata = {
                "finding": json.dumps(finding),
                "rule_id": finding['rule_id'],
                "severity": finding['severity'],
                "path": finding['path']
            }
            
            documents.append(doc)
            metadatas.append(metadata)
            ids.append(f"finding_{i}")
        
        self.findings_collection.add(
            documents=documents,
            metadatas=metadatas,
            ids=ids
        )

    def search(self, query: str, limit: int = 5) -> List[Dict]:
        """Search for findings using natural language query."""
        results = self.findings_collection.query(
            query_texts=[query],
            n_results=limit
        )
        
        findings = []
        for metadata in results['metadatas'][0]:
            finding = json.loads(metadata['finding'])
            findings.append(finding)
        
        return findings

    def get_related_findings(self, finding: Dict, limit: int = 5) -> List[Dict]:
        """Get findings related to a specific finding."""
        query = f"""
        Rule: {finding['rule_id']}
        Message: {finding['message']}
        Code: {finding['code']}
        """
        
        return self.search(query, limit)

    def get_finding_by_id(self, finding_id: str) -> Dict:
        """Retrieve a specific finding by its ID."""
        result = self.findings_collection.get(ids=[finding_id])
        if result['metadatas']:
            return json.loads(result['metadatas'][0]['finding'])
        return None
