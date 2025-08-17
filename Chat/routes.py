from flask import render_template, request, session, redirect, url_for
from . import app, socketio
from flask_socketio import emit, join_room, leave_room
import json
from datetime import datetime

# Store active users and chat history in memory
# In a production environment, you would use a database
active_users = {}
chat_history = []
MAX_HISTORY = 100  # Maximum number of messages to store

@app.route('/')
def index():
    """Chat home page"""
    return render_template('chat_index.html')

@app.route('/chat')
def chat():
    """Main chat page"""
    username = request.args.get('username')
    room = request.args.get('room', 'general')
    
    if not username:
        return redirect(url_for('index'))
    
    return render_template('chat.html', username=username, room=room)

@socketio.on('connect')
def handle_connect():
    """Handle client connection"""
    emit('status', {'message': 'Connected to server'})
    
@socketio.on('disconnect')
def handle_disconnect():
    """Handle client disconnection"""
    if 'username' in session and 'room' in session:
        username = session['username']
        room = session['room']
        
        # Remove user from active users
        if room in active_users and username in active_users[room]:
            active_users[room].remove(username)
            
        # Notify others that user has left
        emit('user_left', {'username': username}, room=room)
        leave_room(room)

@socketio.on('join')
def handle_join(data):
    """Handle user joining a chat room"""
    username = data.get('username')
    room = data.get('room', 'general')
    
    if not username:
        return
    
    # Store user session data
    session['username'] = username
    session['room'] = room
    
    # Add user to room
    join_room(room)
    
    # Add user to active users list
    if room not in active_users:
        active_users[room] = []
    if username not in active_users[room]:
        active_users[room].append(username)
    
    # Send welcome message
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    join_message = {
        'username': 'System',
        'message': f'{username} has joined the chat',
        'timestamp': timestamp
    }
    
    emit('message', join_message, room=room)
    
    # Send list of active users to the new user
    emit('active_users', {'users': active_users[room]}, room=request.sid)
    
    # Notify others about the new user
    emit('user_joined', {'username': username}, room=room, include_self=False)
    
    # Send chat history to new user
    room_history = [msg for msg in chat_history if msg.get('room') == room]
    emit('chat_history', {'history': room_history}, room=request.sid)

@socketio.on('leave')
def handle_leave(data):
    """Handle user leaving a chat room"""
    username = data.get('username')
    room = data.get('room', 'general')
    
    if not username:
        return
    
    # Remove user from room
    leave_room(room)
    
    # Remove user from active users
    if room in active_users and username in active_users[room]:
        active_users[room].remove(username)
    
    # Clear session
    session.pop('username', None)
    session.pop('room', None)
    
    # Notify others that user has left
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    leave_message = {
        'username': 'System',
        'message': f'{username} has left the chat',
        'timestamp': timestamp
    }
    
    emit('message', leave_message, room=room)
    emit('user_left', {'username': username}, room=room)

@socketio.on('send_message')
def handle_message(data):
    """Handle new chat message"""
    username = data.get('username')
    room = data.get('room', 'general')
    message = data.get('message', '').strip()
    
    if not username or not message:
        return
    
    # Create message object
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    msg_obj = {
        'username': username,
        'message': message,
        'room': room,
        'timestamp': timestamp
    }
    
    # Add to chat history
    chat_history.append(msg_obj)
    
    # Limit chat history size
    if len(chat_history) > MAX_HISTORY:
        chat_history.pop(0)
    
    # Broadcast message to room
    emit('message', msg_obj, room=room)

@socketio.on('get_active_users')
def handle_get_users(data):
    """Return list of active users in a room"""
    room = data.get('room', 'general')
    
    if room in active_users:
        emit('active_users', {'users': active_users[room]})
    else:
        emit('active_users', {'users': []})
