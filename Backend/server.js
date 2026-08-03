/*
 * Main server configuration for the DiscountMate backend.
 * This file sets up security controls, CORS, payload limits, input sanitisation,
 * API routes, database connections, error handling and supporting services.
 */


// Import Express to create the DiscountMate backend server.
const express = require('express');

// Import CORS to control which frontend domains can access the API.
const cors = require('cors');

// Import Helmet to add security-related HTTP response headers.
const helmet = require('helmet');

const os = require('os');
const path = require('path');
const fs = require('fs');

const {
   SecretManagerServiceClient,
} = require('@google-cloud/secret-manager');

// Import DiscountMate application routes.
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
const reverseImageSearchRoutes = require(
   './src/routers/reverse-image-search.router'
);
const dashboardRoutes = require('./src/routers/dashboard.router');
const notificationRoutes = require('./src/routers/notification.router');
const alertSegmentRoutes = require('./src/routers/alertSegment.router');
const listRoutes = require('./src/routers/list.router');

// Import the global input sanitisation middleware added for CS-10-T1.
const inputSanitisation = require(
   './src/middleware/inputSanitisation.middleware'
);

// Import reverse image search service controls.
const {
   startReverseImageSearch,
   stopReverseImageSearch,
} = require('./src/services/reverseImageSearchProcess');

/*
 * Load local environment variables when the application is not running
 * in production. Production values are provided by the cloud environment.
 */
if (process.env.NODE_ENV !== 'production') {
   require('dotenv').config({
      path: path.join(__dirname, '.env'),
   });
}

// Import Swagger configuration after the environment variables are loaded.
const setupSwagger = require('./src/config/swagger');

// Create the Express application.
const app = express();

/*
 * Remove the default "X-Powered-By: Express" response header.
 *
 * This prevents the backend from unnecessarily revealing that it uses
 * Express and reduces technology information disclosure.
 */
app.disable('x-powered-by');

// Use the configured port or fall back to port 8080.
const PORT = process.env.PORT || 8080;

// Check whether the application is running in production.
const isProduction = process.env.NODE_ENV === 'production';

// Detect managed environments such as Google Cloud Run or App Engine.
const isManagedCloudRuntime = Boolean(
   process.env.K_SERVICE || process.env.GAE_SERVICE
);

/*
 * Read the approved CORS origins from the environment configuration.
 *
 * Multiple trusted origins can be separated using commas.
 */
const allowedOrigins = (process.env.CORS_ORIGIN || '')
   .split(',')
   .map((value) => value.trim())
   .filter(Boolean);

/*
 * Check incoming browser origins against the approved origin list.
 *
 * Requests without an Origin header are allowed because they may come
 * from tools, mobile applications or other backend services.
 */
const corsOrigin =
   allowedOrigins.length === 0
      ? true
      : (origin, callback) => {
           if (!origin || allowedOrigins.includes(origin)) {
              callback(null, true);
              return;
           }

           callback(new Error('Origin not allowed by CORS'));
        };

/*
 * Enable reverse proxy support in production.
 *
 * Managed environments commonly send traffic through a trusted proxy.
 * This allows Express and rate-limiting middleware to identify the
 * correct client IP address.
 */
if (isProduction) {
   // Trust the first proxy hop used by App Engine or Cloud Run.
   app.set('trust proxy', 1);
}

/*
 * Create the temporary uploads directory if it does not already exist.
 */
const uploadsDir =
   process.env.UPLOAD_DIR || path.join(os.tmpdir(), 'uploads');

if (!fs.existsSync(uploadsDir)) {
   fs.mkdirSync(uploadsDir, {
      recursive: true,
   });
}

/*
 * CS-10-T2: Configure strict security headers for normal API responses.
 *
 * Most DiscountMate API endpoints return JSON rather than HTML pages.
 * Therefore, scripts, forms, frames and embedded objects can be blocked.
 */
const apiSecurityHeaders = helmet({
   /*
    * Configure a restrictive Content Security Policy.
    *
    * This reduces the risk of API responses being treated as executable
    * web content by a browser.
    */
   contentSecurityPolicy: {
      /*
       * Disable Helmet's default CSP so the application uses only the
       * explicitly defined policies below.
       */
      useDefaults: false,

      directives: {
         // Block all content types unless they are specifically permitted.
         defaultSrc: ["'none'"],

         // Prevent an attacker from changing the document's base URL.
         baseUri: ["'none'"],

         // Prevent API responses from being used to submit browser forms.
         formAction: ["'none'"],

         /*
          * Prevent API responses from being displayed inside frames or
          * iframes. This reduces clickjacking exposure.
          */
         frameAncestors: ["'none'"],

         // Prevent embedded browser plugins and objects.
         objectSrc: ["'none'"],
      },
   },

   /*
    * Prevent browsers from sending referrer information.
    *
    * This reduces the chance of sensitive URL information being shared
    * with another website.
    */
   referrerPolicy: {
      policy: 'no-referrer',
   },

   /*
    * Enable HTTP Strict Transport Security only in production.
    *
    * HSTS tells browsers to use HTTPS for future connections. It remains
    * disabled during local development because localhost normally uses HTTP.
    */
   strictTransportSecurity: isProduction
      ? {
           // Require HTTPS for one year.
           maxAge: 31536000,

           // Apply the HTTPS requirement to subdomains.
           includeSubDomains: true,
        }
      : false,

   /*
    * Allow uploaded images and other public resources to be loaded by
    * the separate DiscountMate frontend domain.
    */
   crossOriginResourcePolicy: {
      policy: 'cross-origin',
   },
});

/*
 * Configure separate security headers for Swagger documentation.
 *
 * Swagger UI requires JavaScript and CSS to display the API documentation.
 * The strict API Content Security Policy could otherwise stop it from loading.
 */
const swaggerSecurityHeaders = helmet({
   /*
    * Disable CSP only for Swagger so its JavaScript and styles can load.
    * Other Helmet security headers will still be applied.
    */
   contentSecurityPolicy: false,

   // Prevent Swagger pages from sharing referrer information.
   referrerPolicy: {
      policy: 'no-referrer',
   },

   // Enable HTTPS enforcement for Swagger only in production.
   strictTransportSecurity: isProduction
      ? {
           // Require HTTPS for one year.
           maxAge: 31536000,

           // Apply the HTTPS requirement to subdomains.
           includeSubDomains: true,
        }
      : false,

   /*
    * Allow Swagger to load required resources across origins where needed.
    */
   crossOriginResourcePolicy: {
      policy: 'cross-origin',
   },
});

/*
 * Apply the Swagger-compatible headers to documentation requests.
 *
 * All other backend routes receive the stricter API security headers.
 */
app.use((req, res, next) => {
   // Check whether the request is for Swagger documentation.
   if (req.path.startsWith('/api-docs')) {
      // Apply the Swagger-compatible security configuration.
      return swaggerSecurityHeaders(req, res, next);
   }

   // Apply strict security headers to normal API requests.
   return apiSecurityHeaders(req, res, next);
});

/*
 * Configure CORS for approved DiscountMate frontend origins.
 *
 * CS-10-T3 will further review and strengthen this configuration.
 */
app.use(
   cors({
      // Check the request origin using the configured origin allowlist.
      origin: corsOrigin,

      // Allow only the HTTP methods required by DiscountMate.
      methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],

      // Allow authenticated cross-origin requests where required.
      credentials: true,
   })
);

/*
 * CS-10-T1: Request payload limits can be changed through environment
 * variables without changing the application code.
 */
const JSON_BODY_LIMIT =
   process.env.JSON_BODY_LIMIT || '100kb';

const FORM_BODY_LIMIT =
   process.env.FORM_BODY_LIMIT || '50kb';

/*
 * Limit incoming JSON request bodies.
 *
 * This helps prevent oversized payload attacks that could consume server
 * memory and processing resources.
 */
app.use(
   express.json({
      // Reject JSON bodies larger than the configured limit.
      limit: JSON_BODY_LIMIT,

      // Only accept JSON objects and arrays as valid JSON request bodies.
      strict: true,
   })
);

/*
 * Limit URL-encoded form submissions.
 *
 * This restricts the total size, number of parameters and nesting depth
 * accepted by the server.
 */
app.use(
   express.urlencoded({
      /*
       * Allow nested form data while restricting its maximum depth below.
       */
      extended: true,

      // Reject form bodies larger than the configured limit.
      limit: FORM_BODY_LIMIT,

      // Restrict the total number of submitted form parameters.
      parameterLimit: 100,

      // Prevent excessively deep nested form structures.
      depth: 5,
   })
);

/*
 * Inspect request bodies and query strings for unsafe input.
 *
 * This middleware runs after body parsing but before application routes,
 * ensuring dangerous input is blocked before reaching the controllers.
 */
app.use(inputSanitisation);

/*
 * Make files in the temporary uploads directory publicly accessible
 * through the /uploads route.
 */
app.use('/uploads', express.static(uploadsDir));

// Initialize Swagger API documentation.
setupSwagger(app);

/*
 * Load the MongoDB connection string.
 *
 * A locally configured MONGO_URI is used first. If it is unavailable,
 * the value is retrieved from Google Cloud Secret Manager.
 */
async function ensureMongoUri() {
   // Stop if MONGO_URI has already been configured.
   if (process.env.MONGO_URI && process.env.MONGO_URI.trim()) {
      return;
   }

   const secretName =
      process.env.MONGO_URI_SECRET_NAME || 'mongo-uri';

   const client = new SecretManagerServiceClient();

   // Prefer the project ID supplied by the managed cloud environment.
   const projectId =
      process.env.GOOGLE_CLOUD_PROJECT ||
      (await client.getProjectId());

   if (!projectId) {
      throw new Error(
         'GOOGLE_CLOUD_PROJECT is not set and projectId could not be resolved'
      );
   }

   const secretVersionName =
      `projects/${projectId}/secrets/${secretName}/versions/latest`;

   const [version] = await client.accessSecretVersion({
      name: secretVersionName,
   });

   const payload =
      version.payload && version.payload.data
         ? version.payload.data.toString('utf8').trim()
         : '';

   if (!payload) {
      throw new Error(
         `Secret ${secretName} is empty or unreadable`
      );
   }

   // Store the retrieved secret for the database connection module.
   process.env.MONGO_URI = payload;

   // Log only whether the secret was loaded, not the secret itself.
   console.log(
      'MONGO_URI loaded:',
      Boolean(process.env.MONGO_URI)
   );
}

/*
 * Load the JWT signing secret.
 *
 * A locally configured JWT_SECRET is used first. If it is unavailable,
 * the value is retrieved from Google Cloud Secret Manager.
 */
async function ensureJwtSecret() {
   // Stop if JWT_SECRET has already been configured.
   if (
      process.env.JWT_SECRET &&
      process.env.JWT_SECRET.trim()
   ) {
      return;
   }

   const secretName =
      process.env.JWT_SECRET_SECRET_NAME || 'jwt-secret';

   const client = new SecretManagerServiceClient();

   // Prefer the project ID supplied by the managed cloud environment.
   const projectId =
      process.env.GOOGLE_CLOUD_PROJECT ||
      (await client.getProjectId());

   if (!projectId) {
      throw new Error(
         'GOOGLE_CLOUD_PROJECT is not set and projectId could not be resolved'
      );
   }

   const secretVersionName =
      `projects/${projectId}/secrets/${secretName}/versions/latest`;

   const [version] = await client.accessSecretVersion({
      name: secretVersionName,
   });

   const payload =
      version.payload && version.payload.data
         ? version.payload.data.toString('utf8').trim()
         : '';

   if (!payload) {
      throw new Error(
         `Secret ${secretName} is empty or unreadable`
      );
   }

   // Store the retrieved secret for authentication middleware.
   process.env.JWT_SECRET = payload;

   // Log only whether the secret was loaded, not the secret itself.
   console.log(
      'JWT_SECRET loaded:',
      Boolean(process.env.JWT_SECRET)
   );
}

/*
 * Connect to required services before starting the HTTP server.
 */
async function startServer() {
   try {
      // Load authentication and database secrets.
      await ensureJwtSecret();
      await ensureMongoUri();

      /*
       * Import the database module only after MONGO_URI has been loaded.
       */
      const {
         connectToMongoDB,
      } = require('./src/config/database');

      // Connect the DiscountMate backend to MongoDB.
      await connectToMongoDB();
   } catch (err) {
      console.error(
         'Failed to initialize MongoDB:',
         err
      );

      process.exit(1);
   }

   try {
      /*
       * Managed cloud environments use the separately deployed reverse
       * image search service.
       */
      if (isManagedCloudRuntime) {
         console.log(
            'Managed runtime detected. Using reverse image search sidecar via REVERSE_IMAGE_SEARCH_SERVICE_URL.'
         );
      } else {
         /*
          * Start the local reverse image search service during local
          * development.
          */
         await startReverseImageSearch();
      }
   } catch (err) {
      console.error(
         'Failed to start ReverseImageSearch sidecar:',
         err.message
      );

      process.exit(1);
   }

   // Start accepting incoming HTTP requests.
   app.listen(PORT, () => {
      console.log(`Server running on port ${PORT}`);
   });
}

/*
 * DiscountMate API routes.
 */
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
app.use(
   '/api/reverse-image-search',
   reverseImageSearchRoutes
);
app.use('/api/dashboard', dashboardRoutes);
app.use('/api/notifications', notificationRoutes);
app.use('/api/alert-segments', alertSegmentRoutes);
app.use('/api/lists', listRoutes);

/*
 * Root route used to confirm that the API is running.
 */
app.get('/', (req, res) => {
   res.send('Welcome to the DiscountMate API!');
});

/*
 * Global error handling middleware.
 *
 * This must remain after all application routes so it can handle errors
 * passed from middleware, parsers, controllers and route handlers.
 */
app.use((err, req, res, next) => {
   /*
    * Handle oversized JSON and URL-encoded form payloads.
    */
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

   /*
    * Handle files that exceed the upload size configured by Multer.
    */
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

   /*
    * Handle malformed JSON without returning a generic server error.
    */
   if (err.type === 'entity.parse.failed') {
      return res.status(400).json({
         success: false,
         message: 'Invalid JSON request.',
      });
   }

   /*
    * Handle URL-encoded form data that exceeds the allowed nesting depth.
    */
   if (
      err.type === 'querystring.parse.rangeError' ||
      (
         err.status === 400 &&
         err.message === 'The input exceeded the depth'
      )
   ) {
      console.warn(
         'Excessively nested payload blocked',
         {
            ip: req.ip,
            method: req.method,
            path: req.originalUrl,
         }
      );

      return res.status(400).json({
         success: false,
         message:
            'Request payload is nested too deeply.',
      });
   }

   /*
    * Log unexpected errors internally without exposing detailed server
    * information to the user.
    */
   console.error(err.stack);

   return res.status(500).json({
      success: false,
      message: 'Something went wrong!',
   });
});

// Start the DiscountMate backend server.
startServer();

/*
 * Gracefully stop the locally managed reverse image search service when
 * the application receives a shutdown signal.
 */
function shutdown(signal) {
   console.log(
      `Received ${signal}. Shutting down...`
   );

   stopReverseImageSearch();
   process.exit(0);
}

// Handle Ctrl+C and system termination signals.
process.on('SIGINT', () => shutdown('SIGINT'));
process.on('SIGTERM', () => shutdown('SIGTERM'));
