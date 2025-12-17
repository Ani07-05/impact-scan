import json
import os
import yaml

# --- The "AI" Knowledge Base (Simulated) ---
# In production, this could be RAG-retrieved or hardcoded high-quality rules.
KNOWLEDGE_BASE = {
    "@supabase/supabase-js": [
        {
            "id": "supabase-anon-key-hardcoded",
            "patterns": [
                {"pattern": 'createClient($URL, "$KEY", ...)'},
                {"metavariable-regex": {"metavariable": "$KEY", "regex": "(eyJ[a-zA-Z0-9-_]+)"}}
            ],
            "message": "Hardcoded Supabase Anon Key detected. Use process.env.SUPABASE_KEY instead.",
            "severity": "WARNING",
            "languages": ["javascript", "typescript"]
        }
    ],
    "fastapi": [
        {
            "id": "python-cors-wildcard",
            "pattern": 'CORSMiddleware(..., allow_origins=["*"], ..., allow_credentials=True, ...)',
            "message": "CORS with wildcard origin and credentials allowed. This is a security risk.",
            "severity": "ERROR",
            "languages": ["python"]
        }
    ],
    "google-auth": [
         {
            "id": "python-deprecated-google-auth-endpoint",
             "pattern": '"https://accounts.google.com/o/oauth2/auth"',
             "message": "Deprecated Google Auth endpoint detected. Use 'https://accounts.google.com/o/oauth2/v2/auth'.",
             "severity": "WARNING",
             "languages": ["python"]
         },
         {
             "id": "python-oauth-missing-state",
             "patterns": [
                 {"pattern-inside": '$URL = "https://accounts.google.com/o/oauth2/v2/auth...'},
                 {"pattern-not-regex": "state="}
             ],
             "message": "Google OAuth URL missing 'state' parameter. Vulnerable to CSRF.",
             "severity": "ERROR",
             "languages": ["python"]
         }
    ],
    "react": [
        {
            "id": "react-dangerouslysetinnerhtml",
            "pattern": '<$TAG ... dangerouslySetInnerHTML={...} ... />',
            "message": "Detected dangerouslySetInnerHTML. Ensure content is sanitized.",
            "severity": "WARNING",
            "languages": ["javascript", "typescript"]
        }
    ]
}

def scan_dependencies(root_dir):
    detected_libs = set()
    
    # 1. Check package.json
    pkg_path = os.path.join(root_dir, "package.json")
    if os.path.exists(pkg_path):
        with open(pkg_path, 'r') as f:
            data = json.load(f)
            deps = data.get("dependencies", {})
            dev_deps = data.get("devDependencies", {})
            all_deps = {**deps, **dev_deps}
            for dep in all_deps:
                detected_libs.add(dep)
                
    # 2. Check requirements.txt
    req_path = os.path.join(root_dir, "requirements.txt")
    if os.path.exists(req_path):
        with open(req_path, 'r') as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith('#'): continue
                # Basic parsing "lib==version"
                lib_name = line.split('==')[0].split('>=')[0].strip()
                detected_libs.add(lib_name)
                
    return detected_libs

def generate_rules(detected_libs):
    generated_rules = []
    print(f"Detected stack: {detected_libs}")
    
    for lib in detected_libs:
        if lib in KNOWLEDGE_BASE:
            print(f"  [+] Found rules for '{lib}'")
            generated_rules.extend(KNOWLEDGE_BASE[lib])
        else:
            # Maybe use LLM here in real version to generate usage-specific rules?
            pass
            
    return {"rules": generated_rules}

if __name__ == "__main__":
    work_dir = os.path.dirname(os.path.abspath(__file__))
    libs = scan_dependencies(work_dir)
    rules_obj = generate_rules(libs)
    
    output_path = os.path.join(work_dir, "generated_rules.yml")
    with open(output_path, 'w') as f:
        yaml.dump(rules_obj, f, sort_keys=False)
        
    print(f"\n[SUCCESS] Generated {len(rules_obj['rules'])} rules in 'generated_rules.yml'")
