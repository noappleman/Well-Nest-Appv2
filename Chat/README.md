# Real-Time Chat Application

A secure real-time chat application built with Flask-SocketIO that allows users to communicate in different chat rooms.

## Features

- Real-time messaging using WebSockets
- Multiple chat rooms (General, Technology, Random, Support)
- User presence indicators
- Chat history persistence (in-memory)
- Security logging for all chat events
- Input sanitization to prevent XSS attacks

## Requirements

- Python 3.7+
- Flask
- Flask-SocketIO
- Eventlet (for WebSocket support)
- Other dependencies listed in requirements.txt

## Installation

1. Install the required dependencies:

```bash
pip install -r requirements.txt
```

2. Run the chat server:

```bash
python app.py
```

The server will start on port 5002 by default.

## Usage

1. Open a web browser and navigate to `http://localhost:5002`
2. Enter a username and select a chat room
3. Start chatting in real-time with other users

## Security Features

- Input sanitization using MarkupSafe to prevent XSS attacks
- Comprehensive security logging for all chat events
- Session-based user tracking

## Integration with Authentication

The chat application can be integrated with the existing authentication system in the Login module. This would require:

1. Modifying the chat routes to check for authenticated users
2. Using the existing user information instead of asking for a username
3. Adding authentication middleware to protect chat routes

## Future Enhancements

- Persistent chat history using PostgreSQL database
- Private messaging between users
- File sharing capabilities
- User profiles with avatars
- Message read receipts
