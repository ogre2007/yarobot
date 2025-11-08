#!/usr/bin/env python
"""
Test script to verify the web interface works
"""
import os
import sys

# Add the current directory to Python path
sys.path.insert(0, os.path.dirname(__file__))

from yarobot.service import app, template_dir

def test_templates():
    """Test if templates can be loaded"""
    print(f"Template directory: {template_dir}")
    
    # Check if template directory exists
    if not os.path.exists(template_dir):
        print(f"ERROR: Template directory does not exist: {template_dir}")
        return False
    
    # Check if template files exist
    index_template = os.path.join(template_dir, 'index.html')
    base_template = os.path.join(template_dir, 'base.html')
    
    if not os.path.exists(index_template):
        print(f"ERROR: index.html not found in {template_dir}")
        return False
        
    if not os.path.exists(base_template):
        print(f"ERROR: base.html not found in {template_dir}")
        return False
    
    print("✓ Template directory and files exist")
    
    # Test template rendering
    try:
        with app.test_client() as client:
            response = client.get('/')
            if response.status_code == 200:
                print("✓ Index page loads successfully")
                return True
            else:
                print(f"ERROR: Index page returned status {response.status_code}")
                return False
    except Exception as e:
        print(f"ERROR: Template rendering failed: {e}")
        return False

if __name__ == '__main__':
    success = test_templates()
    if success:
        print("\n🎉 Web interface setup is correct!")
        print("\nTo start the server:")
        print("  python -m yarobot.app")
        print("  Then visit: http://localhost:5000")
    else:
        print("\n❌ Web interface setup has issues. Please check the errors above.")
        sys.exit(1)