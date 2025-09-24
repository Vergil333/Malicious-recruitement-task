# 🚀 APOM DApp Backend Server

A comprehensive backend server for the APOM DApp - Gaming & DeFi Platform, providing RESTful APIs and WebSocket support for real-time updates.

## 🌟 Features

### **Core Functionality**
- **Gaming Hub API** - Game management, player stats, tournaments, and rewards
- **DeFi Exchange API** - Pool management, liquidity operations, yield farming, and swaps
- **NFT Marketplace API** - Collection management, trading, minting, and analytics
- **Project Launchpad API** - IDO management, project submissions, and participation
- **DAO Governance API** - Proposal management, voting, and community governance
- **User Management API** - Profiles, achievements, social connections, and portfolios
- **Analytics API** - Platform statistics, market data, and performance metrics

### **Technical Features**
- **RESTful APIs** with comprehensive CRUD operations
- **WebSocket Support** for real-time updates and notifications
- **Mock Data System** with realistic gaming and DeFi data
- **Security Middleware** including CORS, Helmet, and rate limiting
- **Error Handling** with structured error responses
- **Logging & Monitoring** with Morgan and custom logging
- **Modular Architecture** with clean separation of concerns

## 🏗️ Architecture

```
backend/
├── src/
│   ├── server.js          # Main server entry point
│   ├── routes/            # API route handlers
│   │   ├── gaming.js      # Gaming endpoints
│   │   ├── defi.js        # DeFi endpoints
│   │   ├── nft.js         # NFT endpoints
│   │   ├── launchpad.js   # Launchpad endpoints
│   │   ├── governance.js  # Governance endpoints
│   │   ├── user.js        # User management endpoints
│   │   └── analytics.js   # Analytics endpoints
│   ├── data/              # Mock data and data access
│   │   └── mockData.js    # Comprehensive mock data
│   └── websocket/         # WebSocket handlers
│       └── handlers.js    # Real-time update handlers
├── package.json           # Dependencies and scripts
└── env.example           # Environment configuration
```

## 📡 API Endpoints

### **Gaming Hub** (`/api/gaming`)
- `GET /games` - Get all games
- `GET /games/:id` - Get game by ID
- `GET /leaderboard` - Get gaming leaderboard
- `GET /user/:userId/stats` - Get user gaming stats
- `POST /games/:id/start` - Start a game session
- `POST /games/:id/end` - End game session and claim rewards
- `GET /tournaments` - Get game tournaments
- `POST /tournaments/:id/join` - Join tournament

### **DeFi Exchange** (`/api/defi`)
- `GET /pools` - Get all DeFi pools
- `GET /pools/:id` - Get pool by ID
- `GET /overview` - Get DeFi market overview
- `GET /leaderboard` - Get DeFi leaderboard
- `POST /pools/:id/add-liquidity` - Add liquidity to pool
- `POST /pools/:id/remove-liquidity` - Remove liquidity from pool
- `POST /swap` - Execute token swap
- `GET /yield-farming` - Get yield farming opportunities
- `POST /yield-farming/:id/stake` - Stake tokens for yield farming
- `GET /user/:userId/portfolio` - Get user's DeFi portfolio

### **NFT Marketplace** (`/api/nft`)
- `GET /collections` - Get all NFT collections
- `GET /collections/:id` - Get collection by ID
- `GET /collections/:id/nfts` - Get NFTs in a collection
- `GET /nfts` - Get all NFTs with filtering
- `GET /nfts/:id` - Get NFT by ID
- `POST /nfts/:id/list` - List NFT for sale
- `POST /nfts/:id/buy` - Buy NFT
- `GET /stats` - Get marketplace statistics
- `GET /leaderboard` - Get NFT leaderboard
- `POST /collections` - Create new collection
- `POST /mint` - Mint new NFT

### **Project Launchpad** (`/api/launchpad`)
- `GET /projects` - Get all launchpad projects
- `GET /projects/:id` - Get project by ID
- `POST /projects/:id/participate` - Participate in IDO
- `POST /submit-project` - Submit new project
- `GET /stats` - Get launchpad statistics
- `GET /user/:userId/participation` - Get user participation history
- `GET /upcoming` - Get upcoming projects
- `GET /live` - Get live projects

### **DAO Governance** (`/api/governance`)
- `GET /proposals` - Get all governance proposals
- `GET /proposals/:id` - Get proposal by ID
- `POST /proposals` - Create new proposal
- `POST /proposals/:id/vote` - Vote on proposal
- `GET /stats` - Get governance statistics
- `GET /user/:userId/voting-history` - Get user voting history
- `GET /active` - Get active proposals
- `GET /pending` - Get pending proposals
- `GET /proposals/:id/discussion` - Get proposal discussion

### **User Management** (`/api/user`)
- `GET /` - Get all users
- `GET /:id` - Get user by ID
- `GET /:id/profile` - Get user profile
- `PUT /:id/profile` - Update user profile
- `GET /:id/transactions` - Get user transaction history
- `GET /:id/portfolio` - Get user portfolio summary
- `GET /:id/achievements` - Get user achievements
- `GET /:id/connections` - Get user social connections
- `POST /:id/follow` - Follow user
- `DELETE /:id/follow` - Unfollow user

### **Analytics** (`/api/analytics`)
- `GET /overview` - Get platform overview statistics
- `GET /gaming` - Get gaming analytics
- `GET /defi` - Get DeFi analytics
- `GET /nft` - Get NFT analytics
- `GET /governance` - Get governance analytics
- `GET /market-data` - Get real-time market data

## 🔌 WebSocket API

### **Connection**
```javascript
const ws = new WebSocket('ws://localhost:3001');
```

### **Subscribe to Updates**
```javascript
// Market data updates
ws.send(JSON.stringify({
  type: 'subscribe',
  action: 'market_data'
}));

// Game updates
ws.send(JSON.stringify({
  type: 'subscribe',
  action: 'game_updates'
}));

// DeFi pool updates
ws.send(JSON.stringify({
  type: 'subscribe',
  action: 'defi_pools'
}));

// NFT activity updates
ws.send(JSON.stringify({
  type: 'subscribe',
  action: 'nft_activity'
}));

// Governance updates
ws.send(JSON.stringify({
  type: 'subscribe',
  action: 'governance'
}));

// Notifications
ws.send(JSON.stringify({
  type: 'subscribe',
  action: 'notifications'
}));
```

### **Message Types**
- `market_data_update` - Real-time market data
- `game_update` - Game activity updates
- `defi_update` - DeFi pool updates
- `nft_update` - NFT activity updates
- `governance_update` - Governance activity updates
- `notifications` - System notifications

## 🛡️ Security Features

- **CORS Protection** - Configurable cross-origin resource sharing
- **Helmet Security** - Security headers and protection
- **Rate Limiting** - API request rate limiting
- **Input Validation** - Request data validation
- **Error Handling** - Structured error responses
- **Logging** - Comprehensive request logging

## 📊 Mock Data

The server includes comprehensive mock data for:
- **Users** - 3 sample users with profiles and achievements
- **Games** - 4 games (3 live, 1 upcoming) with detailed stats
- **DeFi Pools** - 4 liquidity pools with realistic APY and TVL
- **NFT Collections** - 4 collections with floor prices and volumes
- **Launchpad Projects** - 3 projects in different stages
- **Governance Proposals** - 3 proposals with voting data
- **Market Data** - Platform statistics and tokenomics
- **Leaderboards** - Gaming, DeFi, and NFT rankings

## 🔧 Configuration

### **Environment Variables**
- `PORT` - Server port (default: 3001)
- `NODE_ENV` - Environment mode (development/production)
- `FRONTEND_URL` - Frontend URL for CORS
- `LOG_LEVEL` - Logging level (default: info)

### **Rate Limiting**
- Window: 15 minutes
- Max requests: 100 per window
- Configurable via environment variables

## 🚀 Development

### **Scripts**
```bash
npm run dev      # Start development server with auto-reload
npm start        # Start production server
npm test         # Run tests (when implemented)
```

### **Adding New Routes**
1. Create new route file in `src/routes/`
2. Import and mount in `src/server.js`
3. Follow existing pattern for consistency

### **Adding New Mock Data**
1. Extend `src/data/mockData.js`
2. Add data access functions
3. Update relevant route handlers

## 🔮 Future Enhancements

- **Database Integration** - MongoDB/PostgreSQL support
- **Authentication** - JWT-based user authentication
- **Blockchain Integration** - Smart contract interactions
- **Real-time Analytics** - Advanced metrics and insights
- **Notification System** - Push notifications and alerts
- **File Upload** - Image and document handling
- **Caching** - Redis-based caching layer
- **Testing** - Unit and integration tests

## 📝 API Response Format

### **Success Response**
```json
{
  "success": true,
  "data": { ... },
  "count": 10,
  "timestamp": "2024-04-12T10:30:00.000Z"
}
```

### **Error Response**
```json
{
  "success": false,
  "error": "Error message",
  "message": "Detailed error description"
}
```

## 🤝 Contributing

1. Follow the existing code structure
2. Add comprehensive error handling
3. Include input validation
4. Update documentation
5. Test thoroughly

## 📄 License

MIT License - see LICENSE file for details

## 🆘 Support

For questions or issues:
- Check the API documentation
- Review error logs
- Test with mock data
- Verify environment configuration

---

**Built with ❤️ for the APOM DApp ecosystem** 
