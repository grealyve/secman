# SecMan Security Scanner Dashboard

SecMan is a comprehensive security scanning platform that integrates multiple industry-standard security scanners into a unified dashboard, providing real-time vulnerability assessment and management.

![image](https://github.com/user-attachments/assets/ed9be856-c642-4676-8c0b-a9978736f257)

![image](https://github.com/user-attachments/assets/619ecc95-b0ff-4e31-9e65-392e2989a660)

## Getting Started

### Prerequisites
- Node.js (v14+) for frontend
- Go (v1.22.5+) for backend
- PostgreSQL database
- Redis for token management
- Modern web browser
- Access to security scanner APIs (ZAP, Acunetix, Semgrep)

### Installation

1. Clone the repository
```bash
git clone https://github.com/grealyve/secman.git
cd secman
```

2. Install dependencies
```bash
go mod tidy
npm install
```

3. Start the development server
```bash
npm run dev
```

4. Start the backend server
```bash
go run main.go
```

## Features

### Integrated Security Scanners
- **OWASP ZAP** - Web application security scanner for detecting vulnerabilities in web applications
- **Acunetix** - Automated web vulnerability scanner for comprehensive web security assessment
- **Semgrep** - Static code analysis tool for finding bugs and enforcing code standards

### Powerful Dashboard
- Real-time vulnerability metrics and statistics from a dedicated dashboard API
- Interactive charts for vulnerability distribution
- Scanner-specific data visualization in a tabbed interface
- Comprehensive scan history and reporting with filtering capabilities

### Scan Management
- Start scans directly from the interface with multi-URL support
- Configure scan parameters for each scanner
- Bulk URL scanning capability via file upload
- Detailed scan monitoring and control (pause, abort, delete)

### User & Company Management
- Multi-company support with isolation between organizations
- Role-based access control system with granular permissions
- User registration and authentication with JWT token
- Company-specific scan isolation and reporting

## Architecture

### Backend
SecMan uses a modern Go backend with the following components:

- **Web Framework**: Gin-Gonic for high-performance REST API
- **Database**: PostgreSQL with GORM ORM for data persistence
- **Authentication**: JWT-based authentication with Redis blacklisting for token invalidation
- **Security**: Role-based middleware authorization for all endpoints
- **Models**: Structured data models for Users, Companies, Scans, Findings, and Reports

### Frontend
- **Framework**: React with React Router for navigation
- **UI Library**: Bootstrap for responsive design
- **State Management**: Context API for authentication and app state
- **API Integration**: Fetch API with Bearer token authentication

### Database Schema
The application automatically migrates the following models:
- Companies
- Users
- Scans
- Findings
- Reports
- ScannerSettings

## Dashboard Screenshots

#### Semgrep Findings:
![image](https://github.com/user-attachments/assets/d881f712-8298-4247-8259-b6595ace2635)


#### Owasp ZAP Start Scan:
![image](https://github.com/user-attachments/assets/b9852297-641b-4620-bba9-d8c2ed8b2a87)

#### Acunetix Adding Assets:
![image](https://github.com/user-attachments/assets/3f34fb1d-78d8-42fb-9b96-477875b9ae97)

#### Generating Report:
![image](https://github.com/user-attachments/assets/e4c14f9d-1665-4466-900a-47e7f9e68fca)


## Frontend Routes

The application offers a clean, organized routing structure:

- **Dashboard**: `/` - Main dashboard with summary statistics
- **OWASP ZAP**: 
  - `/owasp-zap/scans` - Manage ZAP scans
  - `/owasp-zap/findings` - View scan findings
  - `/owasp-zap/reports` - Access and download reports
  - `/owasp-zap/generate-report` - Create new reports
- **Acunetix**:
  - `/acunetix/assets` - Manage assets/targets
  - `/acunetix/scans` - Manage scans
  - `/acunetix/findings` - View vulnerabilities
  - `/acunetix/reports` - Access reports
  - `/acunetix/generate-report` - Generate new reports
- **Semgrep**:
  - `/semgrep/scans` - Manage code scans
  - `/semgrep/findings` - View findings
  - `/semgrep/deployments` - Manage deployments
- **Administration**:
  - `/admin` - Admin panel
  - `/user-creation` - Create new users
  - `/company-relation` - Manage company relations
- **User Settings**:
  - `/settings` - Scanner configuration
  - `/profile-settings` - User profile management
- **Help**: `/help` - Documentation and user assistance

## Use Case Diagram

The system supports the following user interactions:

### User Operations
- Login to the system
- View scan results
- Start, stop, and delete scans
- Insert, edit, and delete assets
- Create and download reports

### Admin Operations
- All user operations
- Create, delete and manage users
- Manage authorization and permissions
- Edit system configuration

## Security

The application implements several security measures:
- JWT-based authentication with token blacklisting
- Role-based access control for all endpoints
- Authorization middleware to protect resources
- Token invalidation on logout
- Password hashing for user credentials

## Admin Features

Administrators can manage companies and users through dedicated admin panels:
- Create and manage companies
- Add users to companies
- Register new users
- Promote/demote user roles

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Contact

For questions or support, please contact [ysf.yildiz11@gmail.com)](mailto:ysf.yildiz11@gmail.com).

---

 2025 SecMan Security Platform. All rights reserved.

# SecMan - Security Management Platform

SecMan is a comprehensive security management platform that integrates multiple vulnerability scanners including Acunetix, OWASP ZAP, and Semgrep.

## Features

- **Multi-Scanner Integration**: Supports Acunetix, OWASP ZAP, and Semgrep
- **Vulnerability Management**: Centralized vulnerability tracking and reporting
- **User Management**: Role-based access control with company isolation
- **Dashboard**: Real-time security metrics and analytics
- **Report Generation**: Automated security reports

## Technology Stack

- **Backend**: Go (Gin framework)
- **Frontend**: React (Vite)
- **Database**: PostgreSQL
- **Cache**: Redis
- **Containerization**: Docker & Docker Compose

## Docker Deployment

### Prerequisites

- Docker
- Docker Compose

### Quick Start

1. **Clone the repository**:
```bash
git clone <repository-url>
cd secman
```

2. **Start the application**:
```bash
docker-compose up -d
```

3. **Access the application**:
   - Application: http://localhost:4040
   - Health Check: http://localhost:4040/health

### Services

The Docker setup includes a single all-in-one container:

- **secman_all_in_one**: Contains all services in one container
  - **Port 4040**: Main application (Go backend + React frontend)
  - **Port 5432**: PostgreSQL database with pre-loaded data
  - **Port 6379**: Redis cache for session management

### Database Initialization

The database is automatically initialized with:
- Schema creation with UUID support
- Sample companies, users, and scanner settings
- Historical scan data and findings

### Default Credentials

After deployment, you can use these default accounts:

- **Admin**: admin@admin.com / admin123
- **User**: ysf.yildiz11@gmail.com / password

### Environment Variables

The application supports the following environment variables:

- `DB_HOST`: Database host (default: localhost)
- `DB_PORT`: Database port (default: 5432)
- `DB_USER`: Database user (default: lutenix)
- `DB_PASSWORD`: Database password (default: lutenix)
- `DB_NAME`: Database name (default: lutenix_db)
- `REDIS_URL`: Redis connection string (default: localhost:6379)
- `PORT`: Application port (default: 4040)

### Configuration

The application configuration is managed through `config.yaml`. Update scanner API keys and endpoints as needed:

```yaml
acunetix_ip: "192.168.1.6"
acunetix_port: 3443
acunetix_apikey: "your-acunetix-api-key"

zap_apikey: "your-zap-api-key"

semgrep_apikey: "your-semgrep-api-key"
```

### Health Checks

The all-in-one container includes comprehensive health checks:
- Database: PostgreSQL ready check
- Redis: Ping check  
- Application: HTTP health endpoint
- Uses supervisord to manage all services

### Logs

Application logs are stored in the `app_logs` Docker volume and can be accessed with:

```bash
docker-compose logs -f secman
```

Or check individual service logs:

```bash
# View all logs
docker exec secman_all_in_one tail -f /var/log/supervisor/*.log

# View app logs
docker exec secman_all_in_one tail -f /var/log/supervisor/secman-app.log

# View database logs  
docker exec secman_all_in_one tail -f /var/log/supervisor/postgresql.log

# View Redis logs
docker exec secman_all_in_one tail -f /var/log/supervisor/redis.log
```

### Stopping the Application

```bash
docker-compose down
```

To remove all data (including database):

```bash
docker-compose down -v
```

### Development

For development with hot reloading:

```bash
# Backend development
go run main.go

# Frontend development  
npm run dev
```

### Troubleshooting

1. **Port conflicts**: Ensure ports 4040, 5432, and 6379 are available
2. **Permission issues**: Make sure Docker has appropriate permissions
3. **Database connection**: Check if PostgreSQL service is healthy
4. **Redis connection**: Verify Redis service is running

### API Documentation

The API endpoints are grouped under `/api` prefix:

- `/api/auth/*` - Authentication endpoints
- `/api/dashboard/*` - Dashboard data
- `/api/acunetix/*` - Acunetix scanner integration
- `/api/zap/*` - OWASP ZAP scanner integration
- `/api/semgrep/*` - Semgrep scanner integration
- `/api/admin/*` - Admin management

Visit `/health` for application health status.
