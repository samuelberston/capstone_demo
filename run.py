import os
import sys
# Add the project root to Python path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from scanner.app import app

if __name__ == '__main__':
    # Use a different port to avoid AirTunes conflict
    app.run(debug=True, port=5001) 