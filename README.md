# Swoon - Modern React Frontend

A modern, anonymity-first video chat platform connecting university students across Canadian campuses. Built with React, Tailwind CSS, and Node.js.

## Features

- **Modern UI/UX**: Beautiful, responsive design with Tailwind CSS
- **Three Connection Modes**:
  - 💕 **Love Mode**: Find romantic connections with students from different universities
  - ⚔️ **Rival Mode**: Connect with students from rival universities for friendly competition
  - 🎉 **Fun Mode**: Make new friends across campuses
- **Video Calling**: Real-time video chat with WebRTC
- **Chat System**: Text messaging during and after calls
- **Student Verification**: Secure verification system for university students
- **Admin Panel**: Manage user verifications and system administration
- **Responsive Design**: Works perfectly on desktop and mobile devices

## Tech Stack

### Frontend
- **React 18** - Modern UI framework
- **Tailwind CSS** - Utility-first CSS framework
- **Socket.io Client** - Real-time communication
- **Simple Peer** - WebRTC peer-to-peer connections

### Backend
- **Node.js** - Server runtime
- **Express.js** - Web framework
- **Socket.io** - Real-time bidirectional communication
- **SQLite** - Lightweight database
- **Multer** - File upload handling
- **Bcrypt** - Password hashing
- **Nodemailer** - Email notifications

## Quick Start

### Prerequisites
- Node.js (v16 or higher)
- npm or yarn

### Installation

1. **Clone the repository**
   ```bash
   git clone <repository-url>
   cd swoon
   ```

2. **Install all dependencies**
   ```bash
   npm run install-all
   ```

3. **Build the React app**
   ```bash
   npm run build
   ```

4. **Start the development server**
   ```bash
   npm run dev
   ```

   This will start:
   - Backend server on `http://localhost:3001`
   - React development server on `http://localhost:3000`

### Production Setup

1. **Build the React app**
   ```bash
   npm run build
   ```

2. **Start the production server**
   ```bash
   npm start
   ```

   The app will be available at `http://localhost:3001`

## Project Structure

```
swoon/
├── client/                 # React frontend
│   ├── public/            # Static assets
│   ├── src/
│   │   ├── components/    # React components
│   │   │   ├── Landing.js
│   │   │   ├── Login.js
│   │   │   ├── Register.js
│   │   │   ├── ModeSelection.js
│   │   │   ├── CallScreen.js
│   │   │   ├── Messages.js
│   │   │   └── Admin.js
│   │   ├── App.js         # Main app component
│   │   └── index.js       # App entry point
│   └── package.json
├── server.js              # Express server
├── users.db               # SQLite database
├── uploads/               # File uploads
└── package.json
```

## Key Components

### Landing Page
- Modern hero section with feature highlights
- Clear call-to-action buttons
- Responsive design for all devices

### Authentication
- **Login**: Email/password authentication
- **Register**: Comprehensive registration with file uploads
- Student ID verification system

### Mode Selection
- Three distinct modes with visual indicators
- Interactive card selection
- Clear mode descriptions

### Video Calling
- WebRTC peer-to-peer video calls
- Real-time chat during calls
- Swipe left/right functionality
- Timer and call controls

### Messages
- Persistent chat with matched users
- Organized by connection mode
- Real-time message updates

### Admin Panel
- User verification management
- Photo review system
- Approval/rejection workflow

## Environment Variables

Create a `.env` file in the root directory:

```env
PORT=3001
ADMIN_SECRET=your_admin_secret_here
NODE_ENV=development
```

## API Endpoints

### Authentication
- `POST /register` - User registration
- `POST /login` - User login

### Video Calling
- `GET /socket.io/` - WebSocket connection
- Socket events: `findPartner`, `signal`, `endCall`, `chatMessage`

### Admin
- `GET /admin/pending-users` - Get pending verifications
- `POST /admin/approve-user/:id` - Approve user
- `POST /admin/reject-user/:id` - Reject user

## Development

### Running in Development Mode
```bash
npm run dev
```

### Building for Production
```bash
npm run build
```

### Database Management
The app uses SQLite for simplicity. The database file (`users.db`) is created automatically on first run.

### File Uploads
Student verification photos are stored in the `uploads/` directory. Make sure this directory has write permissions.

## Security Features

- **Password Hashing**: Bcrypt with salt rounds
- **Rate Limiting**: Express rate limiter
- **File Upload Validation**: Multer with file type restrictions
- **CORS Protection**: Configured for development and production
- **Admin Authentication**: Secret-based admin access

## Browser Support

- Chrome 80+
- Firefox 75+
- Safari 13+
- Edge 80+

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Test thoroughly
5. Submit a pull request

## License

This project is for educational purposes only.

## Support

For support or questions, please open an issue in the repository.

---

**Swoon** - Connecting university students across Canada, one video call at a time. 🎓✨ 