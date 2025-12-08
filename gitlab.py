#!/usr/bin/env python3
"""
GitLab CI/CD Variables (Secrets) Auditor
Fetches and lists all accessible CI/CD variables across projects
"""

import requests
import json
import sys
from datetime import datetime
from typing import List, Dict

class GitLabSecretsAuditor:
    def __init__(self, token: str, gitlab_url: str = "https://gitlab.com"):
        self.token = token
        self.gitlab_url = gitlab_url.rstrip('/')
        self.headers = {
            "PRIVATE-TOKEN": token,
            "Content-Type": "application/json"
        }
    
    def get_all_projects(self) -> List[Dict]:
        """Fetch all accessible projects"""
        projects = []
        page = 1
        per_page = 100
        
        print("🔍 Fetching accessible projects...")
        
        while True:
            url = f"{self.gitlab_url}/api/v4/projects"
            params = {
                "membership": "true",
                "per_page": per_page,
                "page": page,
                "simple": "true"
            }
            
            try:
                response = requests.get(url, headers=self.headers, params=params)
                response.raise_for_status()
                
                page_projects = response.json()
                if not page_projects:
                    break
                
                projects.extend(page_projects)
                print(f"   Found {len(projects)} projects so far...")
                
                # Check if there are more pages
                if 'x-next-page' not in response.headers or not response.headers['x-next-page']:
                    break
                    
                page += 1
                
            except requests.exceptions.RequestException as e:
                print(f"❌ Error fetching projects: {e}")
                break
        
        print(f"✅ Total projects found: {len(projects)}\n")
        return projects
    
    def get_project_variables(self, project_id: int) -> List[Dict]:
        """Fetch CI/CD variables for a specific project"""
        url = f"{self.gitlab_url}/api/v4/projects/{project_id}/variables"
        
        try:
            response = requests.get(url, headers=self.headers)
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException:
            return []
    
    def audit_secrets(self) -> Dict:
        """Main audit function"""
        projects = self.get_all_projects()
        
        results = {
            "audit_date": datetime.now().isoformat(),
            "total_projects": len(projects),
            "projects_with_secrets": 0,
            "total_secrets": 0,
            "projects": []
        }
        
        print("🔐 Scanning for CI/CD variables (secrets)...\n")
        
        for idx, project in enumerate(projects, 1):
            project_id = project['id']
            project_path = project['path_with_namespace']
            
            print(f"[{idx}/{len(projects)}] Checking: {project_path}", end="")
            
            variables = self.get_project_variables(project_id)
            
            if variables:
                print(f" ✓ ({len(variables)} secrets)")
                results["projects_with_secrets"] += 1
                results["total_secrets"] += len(variables)
                
                project_data = {
                    "id": project_id,
                    "name": project['name'],
                    "path": project_path,
                    "web_url": project['web_url'],
                    "variables": []
                }
                
                for var in variables:
                    project_data["variables"].append({
                        "key": var.get('key'),
                        "protected": var.get('protected', False),
                        "masked": var.get('masked', False),
                        "environment_scope": var.get('environment_scope', '*'),
                        "variable_type": var.get('variable_type', 'env_var')
                    })
                
                results["projects"].append(project_data)
            else:
                print(" - (no secrets)")
        
        return results
    
    def save_results(self, results: Dict, filename: str = "gitlab_secrets_audit.json"):
        """Save results to JSON file"""
        with open(filename, 'w') as f:
            json.dump(results, f, indent=2)
        print(f"\n💾 Results saved to: {filename}")
    
    def display_summary(self, results: Dict):
        """Display a formatted summary in the CLI"""
        print("\n" + "="*80)
        print("📊 GITLAB CI/CD VARIABLES AUDIT SUMMARY")
        print("="*80)
        print(f"Audit Date: {results['audit_date']}")
        print(f"Total Projects Scanned: {results['total_projects']}")
        print(f"Projects with Secrets: {results['projects_with_secrets']}")
        print(f"Total Secrets Found: {results['total_secrets']}")
        print("="*80 + "\n")
        
        if not results['projects']:
            print("No secrets found in any accessible projects.")
            return
        
        # Sort projects by number of variables (descending)
        sorted_projects = sorted(
            results['projects'], 
            key=lambda x: len(x['variables']), 
            reverse=True
        )
        
        for project in sorted_projects:
            print(f"\n📁 Project: {project['name']}")
            print(f"   Path: {project['path']}")
            print(f"   URL: {project['web_url']}")
            print(f"   Secrets: {len(project['variables'])}")
            print("   " + "-"*76)
            
            for var in sorted(project['variables'], key=lambda x: x['key']):
                flags = []
                if var['protected']:
                    flags.append("🔒 Protected")
                if var['masked']:
                    flags.append("🎭 Masked")
                
                scope = var['environment_scope']
                var_type = var['variable_type']
                
                flag_str = " | ".join(flags) if flags else "No flags"
                print(f"   • {var['key']}")
                print(f"     Type: {var_type} | Scope: {scope} | {flag_str}")
        
        print("\n" + "="*80)


def main():
    print("="*80)
    print("GitLab CI/CD Variables (Secrets) Auditor")
    print("="*80 + "\n")
    
    # Get token from command line or prompt
    if len(sys.argv) > 1:
        token = sys.argv[1]
    else:
        token = input("Enter your GitLab Personal Access Token: ").strip()
    
    if not token:
        print("❌ Error: Token is required")
        sys.exit(1)
    
    # Optional: custom GitLab URL
    gitlab_url = "https://gitlab.com"
    if len(sys.argv) > 2:
        gitlab_url = sys.argv[2]
    
    print(f"Using GitLab instance: {gitlab_url}\n")
    
    # Run audit
    auditor = GitLabSecretsAuditor(token, gitlab_url)
    results = auditor.audit_secrets()
    
    # Save to file
    auditor.save_results(results)
    
    # Display summary
    auditor.display_summary(results)


if __name__ == "__main__":
    main()
