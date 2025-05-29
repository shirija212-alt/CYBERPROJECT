# Deploy INSAFE to Render

## Prerequisites
1. Create a Render account at https://render.com
2. Connect your GitHub/GitLab repository

## Deployment Steps

### 1. Create PostgreSQL Database
1. Go to Render Dashboard > New > PostgreSQL
2. Name: `insafe-db`
3. Database Name: `insafe`
4. User: `insafe_user`
5. Plan: Free (or Starter for production)
6. Click "Create Database"
7. Save the connection string (DATABASE_URL)

### 2. Deploy Web Service
1. Go to Render Dashboard > New > Web Service
2. Connect your repository
3. Configure:
   - **Name**: `insafe-platform`
   - **Environment**: `Node`
   - **Build Command**: `npm install && npm run build`
   - **Start Command**: `npm start`
   - **Plan**: Free (or Starter for production)

### 3. Environment Variables
Add these environment variables in Render:
- `NODE_ENV`: `production`
- `DATABASE_URL`: (Copy from your PostgreSQL database)
- `CYBER_CRIME_PORTAL_API_KEY`: (Optional - for real government integration)
- `OPENAI_API_KEY`: (Optional - for enhanced AI features)

### 4. Domain Configuration
- Your app will be available at: `https://insafe-platform.onrender.com`
- You can add a custom domain in Render settings

## Database Setup
After deployment, run these commands to set up your database:
```bash
npm run db:push
```

## Features Available After Deployment
- Full INSAFE cybersecurity platform
- AI-powered threat detection
- Real-time threat intelligence
- Smart report verification
- Mobile app API endpoints
- PostgreSQL data persistence

## Production Considerations
1. **API Keys**: Add real government API keys for production
2. **Custom Domain**: Configure your own domain
3. **Monitoring**: Set up Render monitoring and alerts
4. **Backup**: Configure automatic database backups
5. **Scaling**: Upgrade to paid plans for higher traffic

## Support
- Render docs: https://render.com/docs
- INSAFE platform is ready for production use