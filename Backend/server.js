const express = require('express');
const cors = require('cors');
const os = require('os');
const path = require('path');
const fs = require('fs');
const { SecretManagerServiceClient } = require('@google-cloud/secret-manager');
// const { connectToMongoDB } = require('./src/config/database');
const userRoutes = require('./src/routers/user.router');
const productRoutes = require('./src/routers/product.router');
const categoryRoutes = require('./src/routers/category.router');
const blogRoutes = require('./src/routers/blog.router');
const newsRoutes = require('./src/routers/news.router');
const contactRoutes = require('./src/routers/contact.router');
const basketRoutes = require('./src/routers/basket.router');
const shoppingListRoutes = require('./src/routers/shopping-list.router');
const mlRoutes = require('./src/routers/ml.router');
const analyticsRoutes = require('./src/routers/analytics.router');
const reverseImageSearchRoutes = require('./src/routers/reverse-image-search.router');
const { startReverseImageSearch, stopReverseImageSearch } = require('./src/services/reverseImageSearchProcess');
const dashboardRoutes = require('./src/routers/dashboard.router');
const notificationRoutes = require('./src/routers/notification.router');
const alertSegmentRoutes = require('./src/routers/alertSegment.router');
const listRoutes = require('./src/routers/list.router');
const inputSanitisation = require('./src/middleware/inputSanitisation.middleware');

if (process.env.NODE_ENV !== 'production') {
   require('dotenv').config({ path: path.join(__dirname, '.env') });
}

const setupSwagger = require('./src/config/swagger');

const app = express();
const PORT = process.env.PORT || 8080;
const isManagedCloudRuntime = Boolean(process.env.K_SERVICE || process.env.GAE_SERVICE);
const allowedOrigins = (process.env.CORS_ORIGIN || "")
   .split(",")
   .map((value) => value.trim())
   .filter(Boolean);

const corsOrigin =
   allowedOrigins.length === 0
      ? true
      : (origin, callback) => {
         if (!origin || allowedOrigins.includes(origin)) {
            callback(null, true);
            return;
         }

         callback(new Error("Origin not allowed by CORS"));
      };

// Reverse proxy support for managed runtimes such as App Engine and Cloud Run.
// express-rate-limit validates X-Forwarded-For usage and will throw if proxies are sending the header but Express isn't configured to trust them.
if (process.env.NODE_ENV === 'production') {
    // Trust the first proxy hop (works for App Engine / common ingress setups)
    app.set('trust proxy', 1);
}

const uploadsDir = process.env.UPLOAD_DIR || path.join(os.tmpdir(), "uploads");
if (!fs.existsSync(uploadsDir)) {
    fs.mkdirSync(uploadsDir, { recursive: true });
}

const helmet =require('helmet');
// Use Helmet to set security headers including Content Security Policy
app.use(helmet({
    contentSecurityPolicy: {
        directives: {
            defaultSrc: ["'self'"],
            scriptSrc: ["'self'"],
            objectSrc: ["'none'"],
            imgSrc: ["'self'", "data:"],
            styleSrc: ["'self'", "https:"]
        }
    }
}));

// CORS Configuration
app.use(cors({
    origin: corsOrigin,
    methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
    credentials: true
}));

// Middleware
// Request payload limits can be changed through environment variables.
const JSON_BODY_LIMIT = process.env.JSON_BODY_LIMIT || '100kb';
const FORM_BODY_LIMIT = process.env.FORM_BODY_LIMIT || '50kb';

// Limit JSON payloads to reduce oversized payload attacks.
app.use(
  express.json({
    limit: JSON_BODY_LIMIT,
    strict: true,
  })
);

// Limit form payload size, parameter count and nesting depth.
app.use(
  express.urlencoded({
    extended: true,
    limit: FORM_BODY_LIMIT,
    parameterLimit: 100,
    depth: 5,
  })
);

// Check request bodies and query strings for unsafe input.
app.use(inputSanitisation);

app.use('/uploads', express.static(uploadsDir));

// Initialize Swagger
setupSwagger(app);

async function ensureMongoUri() {
   if (process.env.MONGO_URI && process.env.MONGO_URI.trim()) {
      return;
   }

   const secretName = process.env.MONGO_URI_SECRET_NAME || 'mongo-uri';
   const client = new SecretManagerServiceClient();

   // Prefer App Engine-provided project id
   const projectId = process.env.GOOGLE_CLOUD_PROJECT || await client.getProjectId();
   if (!projectId) {
      throw new Error("GOOGLE_CLOUD_PROJECT is not set and projectId could not be resolved");
   }

   const secretVersionName = `projects/${projectId}/secrets/${secretName}/versions/latest`;

   const [version] = await client.accessSecretVersion({ name: secretVersionName });
   const payload = version.payload && version.payload.data
      ? version.payload.data.toString('utf8').trim()
      : '';

   if (!payload) {
      throw new Error(`Secret ${secretName} is empty or unreadable`);
   }

   process.env.MONGO_URI = payload;

   console.log("MONGO_URI loaded:", Boolean(process.env.MONGO_URI));
}

async function ensureJwtSecret() {
   if (process.env.JWT_SECRET && process.env.JWT_SECRET.trim()) {
      return;
   }

   const secretName = process.env.JWT_SECRET_SECRET_NAME || "jwt-secret";
   const client = new SecretManagerServiceClient();

   // Prefer App Engine-provided project id
   const projectId = process.env.GOOGLE_CLOUD_PROJECT || (await client.getProjectId());
   if (!projectId) {
      throw new Error("GOOGLE_CLOUD_PROJECT is not set and projectId could not be resolved");
   }

   const secretVersionName = `projects/${projectId}/secrets/${secretName}/versions/latest`;
   const [version] = await client.accessSecretVersion({ name: secretVersionName });

   const payload =
      version.payload && version.payload.data
         ? version.payload.data.toString("utf8").trim()
         : "";

   if (!payload) {
      throw new Error(`Secret ${secretName} is empty or unreadable`);
   }

   process.env.JWT_SECRET = payload;
   console.log("JWT_SECRET loaded:", Boolean(process.env.JWT_SECRET));
}

async function startServer() {
   try {
      await ensureJwtSecret();
      await ensureMongoUri();

      // Require AFTER MONGO_URI is set
      const { connectToMongoDB } = require('./src/config/database');
      await connectToMongoDB();
   } catch (err) {
      console.error("Failed to initialize MongoDB:", err);
      process.exit(1);
   }

   try {
      if (isManagedCloudRuntime) {
         console.log('Managed runtime detected. Using reverse image search sidecar via REVERSE_IMAGE_SEARCH_SERVICE_URL.');
      } else {
         await startReverseImageSearch();
      }
   } catch (err) {
      console.error('Failed to start ReverseImageSearch sidecar:', err.message);
      process.exit(1);
   }

   app.listen(PORT, () => {
      console.log(`Server running on port ${PORT}`);
   });
}

// Routes
app.use('/api/users', userRoutes);
app.use('/api/products', productRoutes);
app.use('/api/categories', categoryRoutes);
app.use('/api/baskets', basketRoutes);
app.use('/api/shopping-lists', shoppingListRoutes);
app.use('/api/blogs', blogRoutes);
app.use('/api/news', newsRoutes);
app.use('/api/contact', contactRoutes);
app.use('/api/ml', mlRoutes);
app.use('/api/analytics', analyticsRoutes);
app.use('/api/reverse-image-search', reverseImageSearchRoutes);
app.use('/api/dashboard', dashboardRoutes);
app.use('/api/notifications', notificationRoutes);
app.use('/api/alert-segments', alertSegmentRoutes);
app.use('/api/lists', listRoutes);

// Root route
app.get('/', (req, res) => {
    res.send('Welcome to the DiscountMate API!');
});

// Global Error Handling Middleware
app.use((err, req, res, next) => {
  // Handle oversized JSON and form payloads.
  if (
    err.type === 'entity.too.large' ||
    err.type === 'parameters.too.many' ||
    err.status === 413
  ) {
    console.warn('Oversized payload blocked', {
      ip: req.ip,
      method: req.method,
      path: req.originalUrl,
    });

    return res.status(413).json({
      success: false,
      message: 'Request payload is too large.',
    });
  }

  // Handle oversized Multer file uploads.
  if (err.code === 'LIMIT_FILE_SIZE') {
    console.warn('Oversized file upload blocked', {
      ip: req.ip,
      method: req.method,
      path: req.originalUrl,
    });

    return res.status(413).json({
      success: false,
      message: 'Uploaded file is too large.',
    });
  }

  // Handle malformed JSON.
  if (err.type === 'entity.parse.failed') {
    return res.status(400).json({
      success: false,
      message: 'Invalid JSON request.',
    });
  }

  // Handle excessively nested form data.
  if (
    err.type === 'querystring.parse.rangeError' ||
    (err.status === 400 && err.message === 'The input exceeded the depth')
  ) {
    console.warn('Excessively nested payload blocked', {
      ip: req.ip,
      method: req.method,
      path: req.originalUrl,
    });

    return res.status(400).json({
      success: false,
      message: 'Request payload is nested too deeply.',
    });
  }

  console.error(err.stack);

  return res.status(500).json({
    success: false,
    message: 'Something went wrong!',
  });
});

// Start the server
startServer();

function shutdown(signal) {
   console.log(`Received ${signal}. Shutting down...`);
   stopReverseImageSearch();
   process.exit(0);
}
process.on('SIGINT',  () => shutdown('SIGINT'));
process.on('SIGTERM', () => shutdown('SIGTERM'));
