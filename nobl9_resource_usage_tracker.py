#!/usr/bin/env python3
"""
Nobl9 Resource Usage Tracker.

This script fetches resource usage data from the Nobl9 Reports API and appends it
to a CSV file for tracking usage over time. Based on the Nobl9 Reports API
documentation.

Usage:
    python nobl9_resource_usage_tracker.py [--context CONTEXT] [--csv-file CSV_FILE]

Dependencies:
    pip install requests toml
"""

import argparse
import base64
import csv
import json
import os
import re
import sys
from datetime import datetime
from typing import Dict, Any, Optional, Tuple

try:
    import requests
    import toml
except ImportError as e:
    print(f"Missing required dependency: {e}")
    print("Install with: pip install requests toml")
    sys.exit(1)


def decode_jwt_payload(token: str) -> Optional[str]:
    """Decode JWT token to extract organization info."""
    try:
        # JWT has three parts: header.payload.signature
        payload_b64 = token.split('.')[1]
        # Add padding if necessary
        payload_b64 += '=' * (-len(payload_b64) % 4)
        payload_json = base64.b64decode(payload_b64).decode('utf-8')
        payload = json.loads(payload_json)
        # Look for organization in m2mProfile
        return payload.get('m2mProfile', {}).get('organization', None)
    except Exception:
        return None


def load_contexts_from_toml() -> Dict[str, Dict[str, Any]]:
    """Load and parse TOML configuration."""
    default_toml_path = os.path.expanduser("~/.config/nobl9/config.toml")
    
    if not os.path.isfile(default_toml_path):
        print("TOML config file not found at expected path:")
        print(f"  {default_toml_path}")
        try:
            user_path = input(
                "Please provide the full path to your Nobl9 config.toml file: "
            ).strip()
            if not os.path.isfile(user_path):
                print(f"ERROR: Could not find TOML file at {user_path}")
                return {}
            toml_path = user_path
        except KeyboardInterrupt:
            print("\nExiting...")
            sys.exit(0)
    else:
        toml_path = default_toml_path
    
    try:
        toml_data = toml.load(toml_path)
        raw_contexts = toml_data.get("contexts", {})
        parsed_contexts = {}
        
        for ctx_name, creds in raw_contexts.items():
            if "clientId" in creds and "clientSecret" in creds:
                # Check if this is a custom instance (has url field)
                is_custom_instance = "url" in creds
                base_url = creds.get("url")
                okta_org_url = creds.get("oktaOrgURL")
                okta_auth_server = creds.get("oktaAuthServer")
                
                parsed_contexts[ctx_name] = {
                    "clientId": creds["clientId"],
                    "clientSecret": creds["clientSecret"],
                    "accessToken": creds.get("accessToken", ""),
                    "organization": creds.get("organization", None),
                    "is_custom_instance": is_custom_instance,
                    "base_url": base_url,
                    "oktaOrgURL": okta_org_url,
                    "oktaAuthServer": okta_auth_server
                }
        return parsed_contexts
    except Exception as e:
        print(f"Failed to parse TOML config: {e}")
        return {}


def enhanced_choose_context() -> Tuple[str, Dict[str, Any]]:
    """Enhanced context selection with custom instance support."""
    contexts_dict = load_contexts_from_toml()
    if not contexts_dict:
        print("No valid contexts found. Please ensure your config.toml is set up correctly.")
        sys.exit(1)
    
    context_names = list(contexts_dict.keys())
    if len(context_names) == 1:
        selected = context_names[0]
        return selected, contexts_dict[selected]
    
    print("\nAvailable contexts:")
    for i, name in enumerate(context_names, 1):
        print(f"  [{i}] {name}")
    
    try:
        choice = input("Select a context: ").strip()
        index = int(choice) - 1
        selected = context_names[index]
        return selected, contexts_dict[selected]
    except (ValueError, IndexError):
        print("ERROR: Invalid context selection.")
        sys.exit(1)
    except KeyboardInterrupt:
        print("\nExiting...")
        sys.exit(0)


def authenticate(credentials: Dict[str, Any]) -> Tuple[str, str]:
    """Authenticate with Nobl9 API using credentials."""
    client_id = credentials.get("clientId")
    client_secret = credentials.get("clientSecret")
    
    if not client_id or not client_secret:
        print("ERROR: Missing credentials in context.")
        sys.exit(1)
    
    org_id = credentials.get("organization")
    # Try decoding accessToken if organization is not in config
    if not org_id and credentials.get("accessToken"):
        org_id = decode_jwt_payload(credentials["accessToken"])
    # Check for SLOCTL_ORGANIZATION environment variable
    if not org_id:
        org_id = os.getenv("SLOCTL_ORGANIZATION")
    # Fall back to user input if no organization ID is found
    if not org_id:
        try:
            org_id = input(
                "Enter Nobl9 Organization ID (find in Nobl9 UI under Settings > Account): "
            ).strip()
        except KeyboardInterrupt:
            print("\nExiting...")
            sys.exit(0)
    
    # Validate org_id
    if not org_id:
        print("ERROR: Organization ID is required.")
        sys.exit(1)
    
    encoded_creds = base64.b64encode(
        f"{client_id}:{client_secret}".encode()
    ).decode()
    
    headers = {
        "Authorization": f"Basic {encoded_creds}",
        "Content-Type": "application/json",
        "Organization": org_id
    }
    
    # Check if this is a custom instance with custom base URL
    is_custom_instance = credentials.get("is_custom_instance", False)
    base_url = credentials.get("base_url")
    okta_org_url = credentials.get("oktaOrgURL")
    okta_auth_server = credentials.get("oktaAuthServer")
    
    if is_custom_instance and base_url:
        print(f"API base url: {base_url}")
        # Use custom base URL for authentication
        auth_url = f"{base_url}/accessToken"
    else:
        auth_url = "https://app.nobl9.com/api/accessToken"
    
    try:
        response = requests.post(auth_url, headers=headers, timeout=30)
        if response.status_code != 200:
            print("ERROR: Authentication failed")
            _handle_auth_error(response)
            sys.exit(1)
        
        token_data = response.json()
        token = token_data.get("access_token")
        if not token:
            print("ERROR: No access token in response")
            print(f"  Response: {response.text}")
            sys.exit(1)
        return token, org_id
        
    except requests.exceptions.Timeout:
        print("ERROR: Authentication request timed out")
        sys.exit(1)
    except requests.exceptions.RequestException as e:
        print(f"ERROR: Network error during authentication: {e}")
        sys.exit(1)
    except json.JSONDecodeError:
        print("ERROR: Invalid JSON response from authentication endpoint")
        print(f"  Response: {response.text}")
        sys.exit(1)


def _handle_auth_error(response: requests.Response) -> None:
    """Handle authentication error responses."""
    try:
        error_data = response.json()
        if "error" in error_data:
            error_info = error_data["error"]
            if isinstance(error_info, str):
                try:
                    json_match = re.search(r'\{.*\}', error_info)
                    if json_match:
                        nested_error = json.loads(json_match.group())
                        print(f"  Error Code: {nested_error.get('errorCode', 'Unknown')}")
                        print(f"  Summary: {nested_error.get('errorSummary', 'No summary provided')}")
                        print(f"  Error ID: {nested_error.get('errorId', 'No ID provided')}")
                        if nested_error.get('errorCauses'):
                            print(f"  Causes: {nested_error['errorCauses']}")
                    else:
                        print(f"  Error: {error_info}")
                except json.JSONDecodeError:
                    print(f"  Error: {error_info}")
            else:
                print(f"  Error Code: {error_info.get('errorCode', 'Unknown')}")
                print(f"  Summary: {error_info.get('errorSummary', 'No summary provided')}")
                print(f"  Error ID: {error_info.get('errorId', 'No ID provided')}")
                if error_info.get('errorCauses'):
                    print(f"  Causes: {error_info['errorCauses']}")
        elif "message" in error_data:
            print(f"  Message: {error_data['message']}")
        else:
            print(f"  Response: {response.text}")
    except json.JSONDecodeError:
        print(f"  Raw response: {response.text}")


def fetch_resource_usage(
    token: str, 
    org: str, 
    is_custom_instance: bool = False, 
    custom_base_url: Optional[str] = None
) -> Dict[str, Any]:
    """Fetch resource usage summary from Nobl9 Reports API."""
    # Use custom base URL for custom instances
    if is_custom_instance and custom_base_url:
        api_base_url = f"{custom_base_url}/reports/v1/usage-summary"
    else:
        api_base_url = "https://app.nobl9.com/api/reports/v1/usage-summary"
    
    headers = {
        "Authorization": f"Bearer {token}",
        "Organization": org,
        "Accept": "application/json; version=v1alpha"
    }
    
    try:
        response = requests.get(api_base_url, headers=headers, timeout=30)
        
        if response.status_code != 200:
            print(f"ERROR: Failed to fetch resource usage (Status: {response.status_code})")
            _handle_api_error(response)
            sys.exit(1)
        
        # DEBUG: Uncomment the lines below to see the full API response JSON
        # This is useful for debugging API responses, understanding data structure,
        # or troubleshooting tier/usage information.
        #
        # print("\n" + "="*60)
        # print("DEBUG: Full API Response JSON")
        # print("="*60)
        # print(json.dumps(response.json(), indent=2))
        # print("="*60)
        # print("DEBUG: End of API Response")
        # print("="*60 + "\n")
        
        return response.json()
        
    except requests.exceptions.Timeout:
        print("ERROR: API request timed out")
        sys.exit(1)
    except requests.exceptions.RequestException as e:
        print(f"ERROR: Network error during API request: {e}")
        sys.exit(1)
    except Exception as e:
        print(f"ERROR: Failed to fetch resource usage: {e}")
        sys.exit(1)


def _handle_api_error(response: requests.Response) -> None:
    """Handle API error responses."""
    try:
        error_data = response.json()
        if "error" in error_data:
            error_info = error_data["error"]
            if isinstance(error_info, str):
                try:
                    json_match = re.search(r'\{.*\}', error_info)
                    if json_match:
                        nested_error = json.loads(json_match.group())
                        print(f"  Error Code: {nested_error.get('errorCode', 'Unknown')}")
                        print(f"  Summary: {nested_error.get('errorSummary', 'No summary provided')}")
                        print(f"  Error ID: {nested_error.get('errorId', 'No ID provided')}")
                    else:
                        print(f"  Error: {error_info}")
                except json.JSONDecodeError:
                    print(f"  Error: {error_info}")
            else:
                print(f"  Error Code: {error_info.get('errorCode', 'Unknown')}")
                print(f"  Summary: {error_info.get('errorSummary', 'No summary provided')}")
                print(f"  Error ID: {error_info.get('errorId', 'No ID provided')}")
        elif "message" in error_data:
            print(f"  Message: {error_data['message']}")
        else:
            print(f"  Response: {response.text}")
    except json.JSONDecodeError:
        print(f"  Raw response: {response.text}")


def append_to_csv(data: Dict[str, Any], csv_file: str, org: str) -> None:
    """Append resource usage data to CSV file."""
    timestamp = datetime.now().isoformat()
    
    # Extract usage data
    usage_summary = data.get("usageSummary", {})
    metadata = data.get("metadata", {})
    
    # Prepare row data
    row = {
        "timestamp": timestamp,
        "organization": org,
        "tier": metadata.get("tier", {}).get("name", ""),
        "generated_at": metadata.get("generatedAt", ""),
        "license_end_date": metadata.get("licenseEndDate", ""),
        
        # SLOs
        "slos_current": usage_summary.get("slos", {}).get("currentUsage", 0),
        "slos_peak": usage_summary.get("slos", {}).get("peakUsage", 0),
        
        # SLO Units
        "slo_units_current": usage_summary.get("sloUnits", {}).get("currentUsage", 0),
        "slo_units_peak": usage_summary.get("sloUnits", {}).get("peakUsage", 0),
        
        # Composite SLO Components
        "composite_slo_current": usage_summary.get("compositeSloComponents", {}).get("currentUsage", 0),
        "composite_slo_peak": usage_summary.get("compositeSloComponents", {}).get("peakUsage", 0),
        
        # Data Sources
        "data_sources_current": usage_summary.get("dataSources", {}).get("currentUsage", 0),
        "data_sources_peak": usage_summary.get("dataSources", {}).get("peakUsage", 0),
        
        # Users
        "users_current": usage_summary.get("users", {}).get("currentUsage", 0),
        "users_peak": usage_summary.get("users", {}).get("peakUsage", 0)
    }
    
    # Check if file exists to determine if we need to write headers
    file_exists = os.path.exists(csv_file)
    
    # Write to CSV
    with open(csv_file, 'a', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=row.keys())
        
        if not file_exists:
            writer.writeheader()
        
        writer.writerow(row)
    
    print(f"SUCCESS: Data appended to {csv_file}")


def display_usage_summary(data: Dict[str, Any]) -> None:
    """Display a summary of the resource usage data."""
    usage_summary = data.get("usageSummary", {})
    
    print("\nUsage Details:")
    print("   Format: Current Usage / Peak Usage")
    print()
    
    # SLOs
    slos = usage_summary.get("slos", {})
    current_slos = slos.get('currentUsage', 0)
    peak_slos = slos.get('peakUsage', 0)
    print(f"   SLOs:           {current_slos:>3} / {peak_slos}")
    
    # SLO Units
    slo_units = usage_summary.get("sloUnits", {})
    current_units = slo_units.get('currentUsage', 0)
    peak_units = slo_units.get('peakUsage', 0)
    print(f"   SLO Units:      {current_units:>3} / {peak_units}")
    
    # Composite SLO Components
    composite_slo = usage_summary.get("compositeSloComponents", {})
    current_composite = composite_slo.get('currentUsage', 0)
    peak_composite = composite_slo.get('peakUsage', 0)
    print(f"   Composite SLOs: {current_composite:>3} / {peak_composite}")
    
    # Data Sources
    data_sources = usage_summary.get("dataSources", {})
    current_ds = data_sources.get('currentUsage', 0)
    peak_ds = data_sources.get('peakUsage', 0)
    print(f"   Data Sources:   {current_ds:>3} / {peak_ds}")
    
    # Users
    users = usage_summary.get("users", {})
    current_users = users.get('currentUsage', 0)
    peak_users = users.get('peakUsage', 0)
    print(f"   Users:          {current_users:>3} / {peak_users}")


def main() -> None:
    """Main function."""
    parser = argparse.ArgumentParser(
        description="Track Nobl9 resource usage and append to CSV file",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python nobl9_resource_usage_tracker.py
  python nobl9_resource_usage_tracker.py --context default
  python nobl9_resource_usage_tracker.py --csv-file usage_tracking.csv
        """
    )
    
    parser.add_argument(
        "--context",
        help="Nobl9 context to use (from TOML config)"
    )
    
    parser.add_argument(
        "--csv-file",
        help="CSV file to append data to (default: nobl9_resource_usage_{org}.csv)"
    )
    
    args = parser.parse_args()
    
    print("Nobl9 Resource Usage Tracker")
    print("=" * 40)
    
    # HARDCODED CREDENTIALS OPTION
    # Uncomment and modify the lines below to use hardcoded credentials instead of
    # TOML configuration. This is useful for automation, CI/CD pipelines, or when
    # you want to avoid interactive context selection.
    #
    # WARNING: Never commit hardcoded credentials to version control!
    # Consider using environment variables for production use.
    #
    # HARDCODED_CREDENTIALS = {
    #     "clientId": "your-client-id-here",
    #     "clientSecret": "your-client-secret-here",
    #     "organization": "your-organization-id-here",
    #     "is_custom_instance": False,  # Set to True for custom Nobl9 instances
    #     "base_url": None,  # Set to custom base URL if using custom instance
    # }
    #
    # If you uncomment the above, the script will skip context selection and
    # use these credentials directly.
    
    # Check if hardcoded credentials are being used
    try:
        HARDCODED_CREDENTIALS
        print("Using hardcoded credentials (skipping context selection)")
        credentials = HARDCODED_CREDENTIALS
        selected_context = "hardcoded"
        is_custom_instance = credentials.get("is_custom_instance", False)
        custom_base_url = credentials.get("base_url")
    except NameError:
        # Use TOML configuration (normal flow)
        if args.context:
            contexts_dict = load_contexts_from_toml()
            if args.context not in contexts_dict:
                print(f"ERROR: Context '{args.context}' not found. Available contexts: {list(contexts_dict.keys())}")
                sys.exit(1)
            selected_context = args.context
            credentials = contexts_dict[selected_context]
        else:
            selected_context, credentials = enhanced_choose_context()
        
        print(f"SUCCESS: Using context: {selected_context}")
        
        # Get custom instance information from credentials
        is_custom_instance = credentials.get("is_custom_instance", False)
        custom_base_url = credentials.get("base_url")
    
    # Authenticate
    print("Authenticating...")
    token, org = authenticate(credentials)
    
    print("SUCCESS: Successfully authenticated with Nobl9")
    
    # Determine CSV filename
    if args.csv_file:
        csv_filename = args.csv_file
    else:
        # Use organization name in default filename
        csv_filename = f"nobl9_resource_usage_{org}.csv"
    
    # Fetch resource usage
    print("Fetching resource usage data...")
    usage_data = fetch_resource_usage(token, org, is_custom_instance, custom_base_url)
    
    # Display summary
    display_usage_summary(usage_data)
    
    # Append to CSV
    append_to_csv(usage_data, csv_filename, org)


if __name__ == "__main__":
    main() 