import chromadb
from chromadb.config import Settings
from pathlib import Path
from typing import List, Dict, Optional, Tuple
import json
import logging

logger = logging.getLogger(__name__)

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

        # Create a separate collection for validation history
        self.validation_history_collection = self.client.get_or_create_collection(
            name="validation_history",
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

    def store_validation_result(self, finding: Dict, validation: Dict):
        """Store a validated finding for learning purposes."""
        try:
            # Create a unique ID based on finding properties
            finding_hash = f"{finding.get('rule_id', '')}_{finding.get('path', '')}_{finding.get('line', 0)}"

            # Create searchable document from finding and validation
            doc = f"""
            Rule: {finding.get('rule_id', 'Unknown')}
            Severity: {finding.get('severity', 'Unknown')}
            Message: {finding.get('message', '')}
            Code: {finding.get('code', '')}
            Verdict: {validation.get('verdict', 'Unknown')}
            Justification: {validation.get('justification', '')}
            Vulnerability Type: {validation.get('vulnerability', {}).get('primary', '')}
            """

            # Store complete data in metadata
            metadata = {
                "finding_data": json.dumps(finding),
                "validation_data": json.dumps(validation),
                "rule_id": finding.get('rule_id', 'Unknown'),
                "severity": finding.get('severity', 'Unknown'),
                "verdict": validation.get('verdict', 'Unknown'),
                "is_valid": str(validation.get('is_valid', False)),
                "confidence": str(validation.get('confidence', 0.0)),
                "risk_score": str(validation.get('risk_score', 0))
            }

            self.validation_history_collection.upsert(
                documents=[doc],
                metadatas=[metadata],
                ids=[finding_hash]
            )

            logger.debug(f"Stored validation result for {finding_hash}")

        except Exception as e:
            logger.error(f"Error storing validation result: {e}")

    def find_similar_validated_findings(self, finding: Dict, limit: int = 5, similarity_threshold: float = 0.7) -> List[Tuple[Dict, Dict, float]]:
        """
        Find similar findings that have been validated before.

        Returns:
            List of tuples: (finding, validation_result, similarity_score)
        """
        try:
            # Create query from current finding
            query = f"""
            Rule: {finding.get('rule_id', '')}
            Message: {finding.get('message', '')}
            Code: {finding.get('code', '')}
            """

            results = self.validation_history_collection.query(
                query_texts=[query],
                n_results=limit
            )

            similar_findings = []
            if results['metadatas'] and results['distances']:
                for i, metadata in enumerate(results['metadatas'][0]):
                    # ChromaDB returns distances (lower is more similar)
                    # Convert to similarity score (0-1, higher is more similar)
                    distance = results['distances'][0][i]
                    similarity = 1.0 - min(distance, 1.0)

                    if similarity >= similarity_threshold:
                        finding_data = json.loads(metadata['finding_data'])
                        validation_data = json.loads(metadata['validation_data'])
                        similar_findings.append((finding_data, validation_data, similarity))

            return similar_findings

        except Exception as e:
            logger.error(f"Error finding similar validated findings: {e}")
            return []

    def get_false_positive_insights(self, finding: Dict) -> Optional[Dict]:
        """
        Get insights about similar false positives to help with validation.

        Returns:
            Dict with insights or None if no similar false positives found
        """
        try:
            similar_findings = self.find_similar_validated_findings(finding, limit=10)

            if not similar_findings:
                return None

            # Filter for false positives and high similarity
            false_positives = [
                (f, v, s) for f, v, s in similar_findings
                if v.get('verdict', '').lower() == 'false positive' and s >= 0.8
            ]

            if not false_positives:
                return None

            # Calculate statistics
            total_similar = len(similar_findings)
            fp_count = len(false_positives)
            avg_similarity = sum(s for _, _, s in false_positives) / fp_count

            # Get common justifications
            justifications = [v.get('justification', '') for _, v, _ in false_positives]

            insights = {
                'similar_false_positives_found': fp_count,
                'total_similar_findings': total_similar,
                'false_positive_rate': fp_count / total_similar if total_similar > 0 else 0,
                'average_similarity': avg_similarity,
                'common_justifications': justifications[:3],  # Top 3
                'suggestion': f"Found {fp_count} similar findings that were false positives (avg similarity: {avg_similarity:.2%}). Consider reviewing carefully."
            }

            return insights

        except Exception as e:
            logger.error(f"Error getting false positive insights: {e}")
            return None

    def get_validation_statistics(self) -> Dict:
        """Get overall statistics about validation history."""
        try:
            # Get all validation records
            results = self.validation_history_collection.get()

            if not results['metadatas']:
                return {
                    'total_validations': 0,
                    'true_positives': 0,
                    'false_positives': 0,
                    'needs_review': 0,
                    'by_rule': {},
                    'by_severity': {}
                }

            stats = {
                'total_validations': len(results['metadatas']),
                'true_positives': 0,
                'false_positives': 0,
                'needs_review': 0,
                'by_rule': {},
                'by_severity': {}
            }

            for metadata in results['metadatas']:
                verdict = metadata.get('verdict', 'Unknown').lower()
                rule_id = metadata.get('rule_id', 'Unknown')
                severity = metadata.get('severity', 'Unknown')

                # Count verdicts
                if 'true positive' in verdict:
                    stats['true_positives'] += 1
                elif 'false positive' in verdict:
                    stats['false_positives'] += 1
                elif 'needs review' in verdict:
                    stats['needs_review'] += 1

                # Count by rule
                stats['by_rule'][rule_id] = stats['by_rule'].get(rule_id, 0) + 1

                # Count by severity
                stats['by_severity'][severity] = stats['by_severity'].get(severity, 0) + 1

            return stats

        except Exception as e:
            logger.error(f"Error getting validation statistics: {e}")
            return {}
