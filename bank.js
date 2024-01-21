// Set up global variables to keep track of wins and runs, Import the express package

process.env.AWS_SDK_LOAD_CONFIG = '1';

function generateMfaCode() {
    const codeLength = 6;
    let code = '';
    for (let i = 0; i < codeLength; i++) {
        code += Math.floor(Math.random() * 10); // Generates a random digit (0-9)
    }
    return code;
}

function sendMfaCode(phoneNumber, mfaCode) {
    // For demo purposes, we're just logging to the console
    console.log(`Sending MFA code ${mfaCode} to ${phoneNumber}`);
}
// isSuspiciousRequest function
function isSuspiciousRequest(req) {
    if (req.url.includes('suspicious')) {
        return true;
    }
    return false;
}
"use strict"
const path = require('path');
const mysql = require('mysql2');
const bcrypt = require('bcrypt');
const express = require('express');
const sessions = require('client-sessions');
var bodyParser = require('body-parser');
const fs = require('fs');
const helmet = require('helmet');
var xssFilters = require('xss-filters');
var bleach = require('bleach');
const https = require('https');
const Web3 = require('web3');
const web3 = new Web3('http://127.0.0.1:7545'); //Ethereum network address
const contractABI = require('./blockchain/build/contracts/BankAppAuth.json').abi; 
const contractAddress = '0x956fd8D26866ADD25342e47A2E9Dfe477aC4E39B'; 
const bankAppAuthContract = new web3.eth.Contract(contractABI, contractAddress);
const chai = require('chai');
const expect = chai.expect;
const session = require('express-session');
const AWS = require('aws-sdk');
const rateLimit = require('express-rate-limit');
const ip = require('ip');
var app = express();
const csrf = require('csurf');
const csrfProtection = csrf({ cookie: true });
const parseForm = bodyParser.urlencoded({ extended: false });

const crypto = require('crypto');
var http = require('http');
var bodyParser = require("body-parser");
const { createSecretKey } = require('crypto');
app.use(bodyParser.urlencoded({ extended: true })); 
app.use(express.urlencoded({ extended: true })); 
app.use(express.json()); 

app.disable('x-powered-by');
app.use(function(req, res, next) {
    res.setHeader("X-Content-Type-Options", "nosniff");
    next();
  });

app.use((req, res, next) => {
    res.setHeader('Strict-Transport-Security', 'max-age=63072000; includeSubDomains; preload');
    next();
});

app.use((req, res, next) => {
    res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate');
    res.setHeader('Pragma', 'no-cache');
    res.setHeader('Expires', '0');
    next();
});

app.use((req, res, next) => {
    res.setHeader('X-Frame-Options', 'DENY'); // Options are DENY, SAMEORIGIN, ALLOW-FROM uri
    next();
  });
  
//Rate Limiting Middleware: This middleware can help prevent brute-force attacks by limiting the number of requests from a single IP address.
const limiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 100 // limit each IP to 100 requests per windowMs
});

app.use(limiter);
app.use(session({
    secret: '30BHb8EqZ5T8yKlcIXcI7IVfqX4QHCbD', 
    resave: false,
    saveUninitialized: false,
    cookie: { secure: true } // Set to true because we are using https
}));
process.env.AWS_SDK_LOAD_CONFIG = '1';

//Setup the CSP to ensure that our program is only running things from the localhost and our server.
/*app.use(helmet.contentSecurityPolicy({
    directives: {
        defaultSrc: ["'self'"],
        scriptSrc: ["'self'", "'unsafe-inline'", "http://localhost:*"],
        styleSrc: ["'self'", "'unsafe-inline'", "http://localhost:*"],
        fontSrc: ["'self'", "https://cdn.scite.ai"] 
        
        }
        })) */
        app.use(
            helmet.contentSecurityPolicy({
              directives: {
                defaultSrc: ["'self'"], 
                scriptSrc: ["'self'"], 
                styleSrc: ["'self'"], 
                imgSrc: ["'self'"], 
                connectSrc: ["'self'"],
                fontSrc: ["'self'", 'https://fonts.gstatic.com'], 
                objectSrc: ["'none'"],
              },
              reportOnly: false, 
            })
          );
          
        let requestCount = {};

        //Intrusion Detection Middleware: This middleware will look for patterns in requests that could indicate a security threat, like repeated requests from the same IP in a short time, requests to sensitive URLs
        const threatDetectionRules = (req) => {
   //IDS rules 
    const suspiciousPatterns = ['/dashboard', '/login'];
    const nonSuspiciousIps = ['127.0.0.1', '::1']; // I added the development IP 
    return suspiciousPatterns.some(pattern => req.url.includes(pattern)) && !nonSuspiciousIps.includes(req.ip);
};

function ipRangeCheck(ipAddress, range) {
    return ip.cidrSubnet(range).contains(ipAddress);
}

app.use((req, res, next) => {
    if (threatDetectionRules(req)) {
        console.warn(`Suspicious request detected: ${req.method} ${req.url} from IP: ${req.ip}`);
        // Optionally block the request, alert admins, etc.
        return res.status(403).send('Access Denied');
    }
    next();
}); 
        
        // Middleware for logging user activities
        app.use((req, res, next) => {
            const username = req.session.username || 'Guest';
            const logEntry = {
                username: username,
                method: req.method,
                url: req.url,
                timestamp: new Date()
            };
        
            // Save the log entry to the database
            const logQuery = 'INSERT INTO UserActivityLogs (username, method, url, timestamp) VALUES (?, ?, ?, ?)';
            mysqlConn.query(logQuery, [logEntry.username, logEntry.method, logEntry.url, logEntry.timestamp], (err, results) => {
                if (err) {
                    console.error('Error logging activity:', err);
                }
            });
        
            next();
        });

        const credentials = new AWS.SharedIniFileCredentials({ profile: 'default' });
        AWS.config.credentials = credentials;
        
           //  AWS Configuration
AWS.config.update({ region: 'eu-north-1' });

const kms = new AWS.KMS();

const keyId = 'arn:aws:kms:eu-north-1:838404538395:key/fdff98e1-9dbd-4803-8e97-08c32e71694e'; 
AWS.config.update({
    accessKeyId: 'AKIA4GNGOAANYWGFGYOP',
    secretAccessKey: '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',         
    region:'eu-north-1' 
  });

  AWS.config.logger = console;

async function encryptData(text) {
    const params = {
        KeyId: keyId,
        Plaintext: Buffer.from(text)
    };
    const data = await kms.encrypt(params).promise();
    return data.CiphertextBlob.toString('base64');
}
console.log(AWS.config.credentials);

//Network Segmentation

function isRequestFromAllowedSegment(ip, allowedSegments) {
    // Normalize IPv6-mapped IPv4 addresses to IPv4
    if (ip.substr(0, 7) === "::ffff:") {
        ip = ip.substr(7);
    }

    // Allowed localhost for development purposes
    if (ip === '127.0.0.1' || ip === '::1') { 
        return true;
    }

    return allowedSegments.some(segment => ipRangeCheck(ip, segment));
}


app.use((req, res, next) => {
    const allowedNetworkSegments = ['192.168.1.0/24', '192.168.2.0/24']; 
    if (!isRequestFromAllowedSegment(req.ip, allowedNetworkSegments)) {
        console.error(`Access attempt from disallowed network segment: ${req.ip}`);
        return res.status(403).send('Access Denied');
    }
    next();
});
//This middleware will log each request for monitoring purposes.
app.use((req, res, next) => {
    console.log(`Request received: ${req.method} ${req.url} from IP: ${req.ip}`);
    next();
});

// Function to decrypt data
async function decryptData(encryptedText) {
    const params = {
        CiphertextBlob: Buffer.from(encryptedText, 'base64')
    };
    const data = await kms.decrypt(params).promise();
    return data.Plaintext.toString('utf8');
}
        // Function for simple anomaly detection
        function detectAnomaly(req) {
            const username = req.session.username || 'Guest';
            const url = req.url;
            const currentTime = new Date().getTime();
        
            // Check for too many requests
            if (!requestCount[username]) {
                requestCount[username] = { count: 1, time: currentTime };
            } else {
                if (currentTime - requestCount[username].time < 60000) { // 60 seconds window
                    requestCount[username].count++;
                    if (requestCount[username].count > 100) { // Threshold for anomaly
                        console.error('Anomaly detected: Too many requests by', username);
                        return true; // Anomaly detected
                    }
                } else {
                    // Reset the count after the time window
                    requestCount[username] = { count: 1, time: currentTime };
                }
            }
        
            // Check for suspicious URLs
            const suspiciousUrls = ['/admin', '/confidential', '/api/internal']; 
            if (suspiciousUrls.includes(url)) {
                console.error('Anomaly detected: Access to suspicious URL', url, 'by', username);
                return true; // Anomaly detected
            }
        
            // No anomalies detected
            return false;
        }
        
        // Middleware for anomaly detection
        app.use((req, res, next) => {
            if (detectAnomaly(req)) {
                // Handle the anomaly
                console.error('Anomaly detected:', req.method, req.url);
                res.status(403).send('Suspicious activity detected.');
            } else {
                next();
            }
        });
//The mysql connection 
var mysqlConn = mysql.createConnection({
    host: "localhost",
    port: "3306",
    user: "root",
    password: "1234Kwadwo",
    database: 'zerotrust',
    multipleStatements: true
});

mysqlConn.connect(err => {
    if (err) {
        console.error('Error connecting to MySQL:', err);
        return;
    }
    console.log('Connected to MySQL');
});

function checkUserRole(requiredRoles) {
    return function(req, res, next) {
        const username = req.session.username; // username is stored in the session
        // Query the database to find the user's roles
        const query = 'SELECT role_name FROM Roles INNER JOIN UserRoles ON Roles.role_id = UserRoles.role_id WHERE UserRoles.username = ?';
        mysqlConn.query(query, [username], function(error, results) {
            if (error) {
                // Handle error...
                return res.status(500).send('Server Error');
            }
            const roles = results.map(row => row.role_name);
            if (requiredRoles.some(role => roles.includes(role))) {
                return next(); // User has one of the required roles
            } else {
                return res.status(403).send('Access Denied'); // User does not have the required role
            }
        });
    }
}

function isAuthenticated(req, res, next) {
    if (req.session && req.session.username) {
        // User is authenticated
        next();
    } else {
        // User is not authenticated
        res.redirect('/login');
    }
}

app.use('/dashboard', isAuthenticated);

//Generate a random number for the cookies to protect the sessions.
var randomNumber=Math.random().toString();
randomNumber=randomNumber.substring(2,randomNumber.length);
app.use(sessions({
  cookieName: 'session',
  secret:  '30BHb8EqZ5T8yKlcIXcI7IVfqX4QHCbD',
  duration: 3 * 60 * 1000 ,
  activeDuration: 5 * 60 * 1000,
  httpOnly: true,
  secure: false,
  ephemeral: true
})); 
 
//Generate a map to help escape html code to avoid XSS attacks.
 var map= {
    '&': '&amp;',
    '<': '&lt;',
    '>': '&gt;',
    '"': '&quot;',
    "'": '&#39;'
};
function escapeHTML(s, forAttribute) {
    return s.replace(forAttribute ? /[&<>'"]/g : /[&<>]/g, function(c) {
        return map[c];
    });
}

//The default page the user tries to go to. If they are logged in, they go to their dashboard, if they are not, they go to the login page.
app.get("/", function(req, resp){
        
    if(req.session.username){
    resp.sendFile(__dirname + "/dashboard.html");   
    }
    else{
    resp.sendFile(__dirname + "/login.html");   
    }
    
});

var brr = []
var count = 0
var accs = []
var a_count = 0
var active = "";

//Access the mysql database for login data.
function processFile(inputFile) {
    count = 0
    brr = []
    mysqlConn.query("USE zerotrust; SELECT * from LoginAccounts;", function(err, qResult){
                    
        if(err) throw err;
    
        qResult[1].forEach(function(account){
        var sma= account['username']
        var smb= account['password']
        var smc= account['salt']
        var mar = [sma, smb, smc]
        brr.push(mar)
        count = count + 1
        });

});

}

//Access the mysql database for balance data.
function processAcc(inputFile) {
    a_count = 0
    accs = []
    mysqlConn.query("USE zerotrust; SELECT * from BalanceAccount;", function(err, qResult){
                    
        if(err) throw err;
        qResult[1].forEach(function(account){
        var sma= account['bName']
        var smb= account['aName']
        var smc= account['amount']
        
       
        var mat = [sma, smb, smc]
        accs.push(mat)
      
        a_count = a_count + 1
        });
    });
    
   
}
processFile('pass.txt');

//For the "login.html" page. Check to see if the login credentials the user inputted are correct.
app.post("/auth", function(req, resp) {
    var username = bleach.sanitize(req.body.username);
    var submittedPassword = bleach.sanitize(req.body.password);

    // Query the database for the user's password hash and phone number
    mysqlConn.query("SELECT password, phoneNumber FROM LoginAccounts WHERE username = ?", [username], function(err, results) {
        if (err) {
            console.error("Database query error:", err);
            return resp.status(500).send("An internal server error occurred.");
        }

        if (results.length > 0) {
            var storedHash = results[0].password;
            var userPhoneNumber = results[0].phoneNumber; // Retrieve the user's phone number from the database

            bcrypt.compare(submittedPassword, storedHash, function(err, isMatch) {
                if (err) {
                    console.error("bcrypt comparison error:", err);
                    return resp.status(500).send("An internal server error occurred.");
                }

                if (isMatch) {

                    
                    // Generate MFA code and send to user 
                    const mfaCode = generateMfaCode();
                    sendMfaCode(userPhoneNumber, mfaCode);

                    // Store MFA code in session with expiration time
                    req.session.mfaCode = mfaCode;
                    req.session.mfaCodeValidUntil = Date.now() + (5 * 60 * 1000); // 5 minutes
                    req.session.tempUsername = username;
                    // Redirect user to MFA page for code verification
                    resp.sendFile(__dirname + '/mfa.html');
                } else {
                    resp.send("Wrong Username or Password");
                }
            });
        } else {
            resp.send("Wrong Username or Password");
        }
    });
});

app.post("/auth", async (req, resp) => {
    var username = bleach.sanitize(req.body.username);
    var submittedPassword = bleach.sanitize(req.body.password);

    // Query the database for the user's password hash and phone number
    mysqlConn.execute("SELECT password, phoneNumber FROM LoginAccounts WHERE username = ?", [username], function(err, results) {
        if (err) {
            console.error("Database query error:", err);
            return resp.status(500).send("An internal server error occurred.");
        }

        if (results.length > 0) {
            var storedHash = results[0].password;
            var userPhoneNumber = results[0].phoneNumber; // Retrieve the user's phone number from the database

            bcrypt.compare(submittedPassword, storedHash, async function(err, isMatch) {
                if (err) {
                    console.error("bcrypt comparison error:", err);
                    return resp.status(500).send("An internal server error occurred.");
                }

                if (isMatch) {
                    // Blockchain validation
                    const passwordHash = web3.utils.sha3(submittedPassword);
                    try {
                        const isValidUser = await bankAppAuthContract.methods.authenticateUser(username, passwordHash).call();
                        if (!isValidUser) {
                            return resp.send("Blockchain authentication failed");
                        }

                        // Generate MFA code here and send to user 
                        const mfaCode = generateMfaCode();
                        sendMfaCode(userPhoneNumber, mfaCode);

                        // Store MFA code in session with expiration time
                        req.session.mfaCode = mfaCode;
                        req.session.mfaCodeValidUntil = Date.now() + (5 * 60 * 1000); // 5 minutes
                        req.session.tempUsername = username;
                        // Redirect user to MFA page for code verification
                        resp.sendFile(__dirname + '/mfa.html');
                    } catch (error) {
                        console.error("Blockchain authentication error:", error);
                        return resp.status(500).send("An internal server error occurred.");
                    }
                } else {
                    resp.send("Wrong Username or Password");
                }
            });
        } else {
            resp.send("Wrong Username or Password");
        }
    });
});

function verifyMfaCode() {
    // AJAX request to verify MFA code
    var xhr = new XMLHttpRequest();
    xhr.open("POST", "/verify-mfa", true);
    xhr.setRequestHeader("Content-Type", "application/json");
    xhr.onreadystatechange = function () {
        if (xhr.readyState === 4 && xhr.status === 200) {
            window.location.href = '/dashboard'; // Redirect to dashboard
        } else if (xhr.readyState === 4) {
            // Handle errors or invalid MFA code
            alert("Invalid MFA code or error occurred.");
        }
    };
    var mfaCode = document.getElementById('mfaCode').value;
    var data = JSON.stringify({"mfaCode": mfaCode});
    xhr.send(data);
}

app.post("/verify-mfa", function(req, res) {
    const userCode = req.body.mfaCode;

    if (req.session.mfaCode === userCode && Date.now() < req.session.mfaCodeValidUntil) {
        // MFA code is valid, complete login
        req.session.username = req.session.tempUsername; // Set the username in the session
        delete req.session.tempUsername; // Clean up the temporary username

        res.redirect('/dashboard');
    } else {
        // Handle MFA verification failure
        res.send("Invalid or expired MFA code. <a href='/login'>Login again</a>");
    }
});

// Endpoint to handle account selection from the dashboard
app.post('/selectAccount', function(req, res) {
    var accountName = req.body.account_name; 
    var accountNumber = req.body.account_number; 

    // Query the database to validate the account name and number
    var query = "SELECT * FROM Accounts WHERE account_name = ? AND account_number = ? LIMIT 1";
mysqlConn.execute(query, [accountName, accountNumber], function(err, results) {
        if (err) {
            // If there's an error during the query, send a 500 Internal Server Error
            console.error('Database query error:', err);
            return res.status(500).json({ message: 'Internal server error' });
        }
        if (results.length > 0) {
            // If the account is found, send back a JSON response with the redirect URL
            // The client-side JavaScript will handle the actual redirection
            return res.json({ redirect: '/balance' });
        } else {
            // If the account is not found, send a 400 Bad Request
            return res.status(400).json({ message: 'Invalid account details' });
        }
    });
});

// Middleware for device authentication
const deviceAuthenticationMiddleware = (req, res, next) => {
    // Perform device authentication checks
    const isDeviceAuthorized = performDeviceAuthentication(req.headers['user-agent']);
    if (isDeviceAuthorized) {
      next();
    } else {
      res.status(401).json({ message: 'Device authentication failed' });
    }
  };
  
  // Protected route requiring device authentication
  app.get('/api/protected', deviceAuthenticationMiddleware, (req, res) => {
    // Access granted only to devices that pass authentication
    res.status(200).json({ message: 'Access granted to protected resource' });
  });
  
  // Network traffic monitoring middleware
  app.use((req, res, next) => {
    // Log network traffic or perform analysis here
    console.log(`Request: ${req.method} ${req.url}`);
    next();
  });
  
  // monitoring suspicious network activity
  app.use((req, res, next) => {
    // Analyze the request for suspicious activity
    if (isSuspiciousRequest(req)) {
      // Take appropriate action, such as logging or blocking the request
      console.log('Suspicious request detected:', req.method, req.url);
      res.status(403).json({ message: 'Forbidden' });
    } else {
      next();
    }
  });
  
//Function that helps escape symbols for when data is received from HTML page to avoid security risks.
function jEscape(Data)
{
     
    var escaped = ""
     
    var charCode = null;
     
   
    var character = null
     
    for(let index = 0; index < Data.length; ++index)
    {
        // The character
        charCode = Data.charCodeAt(index);
         
        // The character
        character = Data.charAt(index);    
         
        var isNum = ((charCode <= 57 && charCode >= 48) || (charCode >= 65 && charCode <= 90) || (charCode >= 97 && charCode <= 122));
         
        if(charCode < 255 && !(isNum))
            // Escape 
            character =  "\\x" + charCode.toString(16);
         
        // Add to the string
        escaped += character
    }
    return escaped;
}

app.get('/dashboard', isAuthenticated, function(req, res) {
    res.sendFile(__dirname + '/dashboard.html');
});

//relate to the "dashboards.html". Send the login account name to display it on the page.
app.post('/accounts', function(req, res){
 
    res.send("<account>" + xssFilters.inHTMLData(bleach.sanitize(req.session.username)) +"</account>");    
});

//bchosen is used to keep track of the chosen balance name the user chooses.
var bchosen = ""

//relate to the  "balance.html". Send balance account to the balance page for use there.
app.post('/aname', function(req, res){
 
    res.send("<account>" + xssFilters.inHTMLData(bchosen) +"</account>");    
});

app.post('/somet', function(req, res){
 
    res.send("<account>" + xssFilters.inHTMLData(bchosen) +"</account>");    
});

//relate to the "dashboard.html". Go to the balance page for the chosen balance account.
app.post('/iacc', function(req, resp){
    var respstring = "";
    bchosen = bchosen.replace(bchosen, "")
 
    bchosen= bchosen + (req.body.chosen)
    
    if(req.session.username){
    resp.sendFile(__dirname + "/balance.html"); 
    }
    else{
    resp.redirect('/');
    }
    
});

//relate to the "balance.html". Generate a list of balance accounts that belong to the login account and are not the current balance account.
app.post('/notthis', function(req, res){
    var iterate3 = 0;
    var lis = "";
    while(iterate3 < a_count){
        if(accs[iterate3][1].toLowerCase() === req.session.username.toLowerCase() && !(accs[iterate3][0] === bchosen))
        {
            lis += "<option value=\"" + jEscape(xssFilters.inHTMLData(accs[iterate3][0])) + "\">" + jEscape(xssFilters.inHTMLData(accs[iterate3][0])) + "</option>";
        }
        iterate3 += 1
    }
    res.send("<lis>" + lis + "</lis>");    
});

//relate to the "balance.html". Display the total amount of money associated with the balance account.
app.post('/currentBalance', function(req, res){
    var iterate4 = 0;
    var liste = "";
    while(iterate4 < a_count){
        if(accs[iterate4][1].toLowerCase() === req.session.username.toLowerCase() && (accs[iterate4][0] === bchosen))
        {
            liste += "<balance>" + accs[iterate4][2] + "</balance>";
        }
        iterate4 += 1
    }
    res.send(liste);    
});

//relate to the "dashboard.html". Generate a list of balance accounts associated with the login account.
app.post('/caccs', function(req, res){
    var iterate2 = 0;
    var lis = "";
    while(iterate2 < a_count){
        if(accs[iterate2][1].toLowerCase() === req.session.username.toLowerCase())
        {
            lis += "<option value= \"" + jEscape(xssFilters.inHTMLData(accs[iterate2][0])) + "\">" + jEscape(xssFilters.inHTMLData(accs[iterate2][0])) + "</option>";
        }
        iterate2 += 1
    }
    res.send("<lis>" + lis + "</lis>");    
});

app.post('/withdraw', isAuthenticated, function(req, res) {
    var username = req.session.username;
    var amount = parseFloat(req.body.amount);
    
    if (isNaN(amount) || amount <= 0) {
        res.status(400).send('Invalid withdrawal amount.');
        return;
    }
    
    var updateBalanceQuery = "UPDATE BalanceAccount SET amount = amount - ? WHERE username = ?";
mysqlConn.execute(updateBalanceQuery, [amount, username], function(error, results) {
        if (error) {
            console.error('Error withdrawing money:', error);
            res.status(500).send('Error withdrawing money.');
            return;
        }
        res.send('Withdrawal successful.');
    });
});


//relate to the "balance.html". Transfer money from the current account to the chosen account 
app.post('/transfer', isAuthenticated, function(req, res) {
    var senderUsername = req.session.username;
    var amount = parseFloat(req.body.amount);
    var recipientUsername = req.body.toUser;

    if (isNaN(amount) || amount <= 0 || !recipientUsername) {
        res.status(400).send('Invalid transfer details.');
        return;
    }

    var withdrawQuery = "UPDATE BalanceAccount SET amount = amount - ? WHERE username = ?";
var depositQuery = "UPDATE BalanceAccount SET amount = amount + ? WHERE username = ?";
    mysqlConn.beginTransaction(function(err) {
        if (err) { throw err; }
        mysqlConn.execute(withdrawQuery, [amount, senderUsername], function(error, results) {
          if (error) {
            return mysqlConn.rollback(function() {
              throw error;
            });
          }
      
          mysqlConn.execute(depositQuery, [amount, recipientUsername], function(error, results) {
            if (error) {
              return mysqlConn.rollback(function() {
                throw error;
              });
            }
            mysqlConn.commit(function(err) {
              if (err) {
                return mysqlConn.rollback(function() {
                  throw err;
                });
              }
              // success message
            });
          });
        });
      });
    });

//Send the user to the chosen balance page.
app.get('/balance', function(req, res)
{
    if(req.session.username){
    res.sendFile(__dirname + "/balance.html");      
    }
    else{
    resp.sendFile(__dirname + "/login.html");   
    }

});
app.get('/currentBalance', isAuthenticated, function(req, res) {
    var username = req.session.username;
    var query = "SELECT amount FROM BalanceAccount WHERE username = ?";
    mysqlConn.query(query, [username], function(error, results, fields) {
        if (error) {
            console.error('Error fetching balance:', error);
            res.status(500).send('Error fetching balance.');
            return;
        }
        if (results.length > 0) {
            res.send({ balance: results[0].amount });
        } else {
            res.send({ balance: 0 }); // Or handle the case where the user has no balance record
        }
    });
});


app.get('/getUsername', isAuthenticated, function(req, res) {
    res.send(req.session.username);
});

//relate to the "balance.html". Deposit money into the current balance account.
app.post('/deposit', isAuthenticated, async (req, res) => {
    try {
        const { amount } = req.body;
        if (!amount || isNaN(amount) || amount <= 0) {
            return res.status(400).json({ success: false, message: 'Invalid deposit amount.' });
        }

        // Assuming `mysqlConn` is a promise-based connection from `mysql2/promise`
        const [result] = await mysqlConn.query('UPDATE BalanceAccount SET amount = amount + ? WHERE username = ?', [amount, req.session.username]);

        if (result.affectedRows === 0) {
            // If no rows were affected, the username was not found
            return res.status(404).json({ success: false, message: 'User not found.' });
        }

        // If deposit is successful
        res.json({ success: true, message: 'Deposit successful.' });

    } catch (error) {
        console.error('Deposit error:', error);
        res.status(500).json({ success: false, message: 'Internal server error.' });
    }
});

//Send the user to the register page
app.get("/register", function(req, resp){
        
    
    resp.sendFile(__dirname + "/register.html");    
    
});
app.get('/login', function(req, resp) {
    resp.sendFile(path.join(__dirname, 'login.html'));
});

//related to the "register.html". Verify that the account the user is trying to create doesn't match another users, and if so, add the account to the database.
app.post("/verify", async function(req, resp) { // Make sure this is async
    var respString = "";
    var username = bleach.sanitize(req.body.username);
    var password = bleach.sanitize(req.body.psw);
    var firstName = bleach.sanitize(req.body.first);
    var lastName = bleach.sanitize(req.body.last);
    var address = bleach.sanitize(req.body.address);
    var phoneNumber = bleach.sanitize(req.body.phone);

    var ver = 0; 
    var iterate = 0;

    // Iterate to check if username is already taken
    while(ver === 0 && iterate < count){
        if(username.toLowerCase() === brr[iterate][0].toLowerCase()){
            ver = 1;
        }
        iterate += 1;
    }

    if(ver === 1){
        resp.send("Username is taken. <a href='/register'>Try again</a>");
    }
    else{
        try {
            // Encrypt sensitive data
            const encryptedFirstName = await encryptData(firstName);
            const encryptedLastName = await encryptData(lastName);
            const encryptedAddress = await encryptData(address);
            const encryptedPhoneNumber = await encryptData(phoneNumber);

            // Hash the password and insert new user into the database
            bcrypt.genSalt(10, function(err, salt) {
                bcrypt.hash(password, salt, function(err, hash) {
                    // Insert user data along with the encrypted phone number into the database
                    mysqlConn.query("INSERT INTO LoginAccounts (username, password, salt, firstName, lastName, address, phoneNumber) VALUES (?, ?, ?, ?, ?, ?, ?);", 
                        [username, hash, salt, encryptedFirstName, encryptedLastName, encryptedAddress, encryptedPhoneNumber], function(err, qResult) {
                            if (err) {
                                // Proper error handling
                                console.error(err);
                                resp.send("Error during registration");
                            } else {
                                // Interact with the smart contract to register the user
                                const passwordHash = web3.utils.sha3(password);
                                web3.eth.getAccounts().then(accounts => {
                                    bankAppAuthContract.methods.registerUser(accounts[0], username, passwordHash, 'role').send({ from: accounts[0] })
                                    .then(function(result) {
                                        req.session.username = username;
                                        req.session.loggedIn = true;
                                        // Successfully registered, redirect to login page
                                        resp.redirect('/login');
                                    })
                                    .catch(function(error) {
                                        console.error("Blockchain registration error:", error);
                                        resp.send("Error during registration on blockchain");
                                    });
                                });
                            }
                    });
                });
            });
        } catch (error) {
            console.error(error);
            resp.send("Error during encryption process");
        }
    }
});

processAcc('accounts.txt');

app.get('/getUsername', isAuthenticated, function(req, res) {
    res.send(req.session.username);
});

//related to the "dashboard.html". Logout the user and resets the session key for the user.
app.get('/logout', function(req, res) {
  req.session.reset();
  res.redirect('/');
});

//related to the "dashboard.html". Allows a user to create a new balance account for their bank account.
app.post("/newacc", function(req, resp){
    //processAcc('accounts.txt');
    var respString = "";
    var accountName = bleach.sanitize(req.body.acc);
    var ver = 0;
    var iterate = 0
    //brr.forEach(function(v) {if(usename.toLowerCase() === brr[v][0].toLowerCase()){ ver = 1}});

    while(ver === 0 && iterate < a_count){
        
            if(accountName.toLowerCase() === accs[iterate][0].toLowerCase()&& active.toLowerCase() === accs[iterate][1].toLowerCase()){
                ver = 1
            }
            
        
        iterate += 1
    }
    if(ver === 1){
    respString += "Account name already used";
    var hls = "<br> Click here to go to dashboard";
    var res = hls.link("/dashboard");
    respString += res;
    resp.send(respString);
    
    }
    else{
    respString += "Account created";
    var hls = "<br> Click here to go to dashboard";
    var res = hls.link("/dashboard");
    respString += res;
    
    mysqlConn.query("USE users; INSERT INTO BalanceAccount VALUES ( ?, ?, ?);", [accountName, active, 0], function(err, qResult){
             if(err) throw err;
             //console.log(qResult[1]); 
             });
            
    processAcc('accounts.txt');
    resp.send(respString);
    }
    

});

//Function to escape data going to the frontend to prevent XSS attacks
function hEscape(Data)
{
     
    var escaped = ""
     
    var charCode = null;
     
   
    var character = null
     
    for(let index = 0; index < Data.length; ++index)
    {
        // The character
        charCode = Data.charCodeAt(index);
         
        // The character
        character = Data.charAt(index);    
         
        // numerical character
        var isNum = ((charCode <= 57 && charCode >= 48) || (charCode >= 65 && charCode <= 90) || (charCode >= 97 && charCode <= 122));
         
        if(charCode < 255 && !(isNum))
            // Escape 
            character =  "&#xHH" + charCode.toString(16);
         
        // Add to the string
        escaped += character
    }
    //console.log(escaped);
    return escaped;
}

app.post('/login', function(req, res) {
    // ... Authenticate user ...
    if (loginSuccessful) {
        req.session.tempUsername = username; // Store username temporarily
        res.redirect('/mfa.html'); // Redirect to MFA page
    } else {
        res.send('Login failed. Please try again.');
    }
});

app.post('/create-account', isAuthenticated, function(req, res) {
    const username = req.session.username; // Retrieve username from session
    const accountName = 'New Account'; // account name
    const accountNumber = Date.now().toString(); // Generate a unique account number

    const query = 'INSERT INTO Accounts (account_name, account_number, username) VALUES (?, ?, ?)';
    db.query(query, [accountName, accountNumber, username], (error, results) => {
        if (error) {
            console.error('Error creating account:', error);
            res.status(500).send('Error creating account.');
            return;
        }
        res.send('Bank account created successfully.');
    });
});
app.get('/accounts', isAuthenticated, function(req, res) {
    const username = req.session.username; // Retrieve username from the session

    // Query to get account details and balance
    const accountQuery = 'SELECT * FROM Accounts WHERE username = ?';
    const balanceQuery = 'SELECT amount FROM BalanceAccount WHERE bName = ?';

    // start by getting the account details
    mysqlConn.query(accountQuery, [username], function(error, accountResults) {
        if (error) {
            console.error('Error fetching account details:', error);
            res.status(500).send('Error fetching account details.');
            return;
        }

        // And then getting the balance
        mysqlConn.query(balanceQuery, [username], function(error, balanceResults) {
            if (error) {
                console.error('Error fetching balance:', error);
                res.status(500).send('Error fetching balance.');
                return;
            }

            const balance = balanceResults.length > 0 ? balanceResults[0].amount : 0;

            // Combine account details and balance in the response
            const response = {
                accounts: accountResults,
                balance: balance
            };

            res.json(response);
        });
    });
});

// Policy Decision Point Function
function policyDecisionPoint(userRoles, requestedResource) {
    // Define the access control rules
    const accessRules = {
        'Customer': ['/customer/dashboard', '/balance', '/transactions'],
        'Employee': ['/employee/dashboard', '/manage', '/reports']
    };

    return userRoles.some(role => accessRules[role] && accessRules[role].includes(requestedResource));
}
// Policy Enforcement Point Middleware
function policyEnforcementPoint(req, res, next) {
    const username = req.session.username; 
    const requestedResource = req.path;

    // Query the database to find the user's roles
    const query = 'SELECT role_name FROM Roles INNER JOIN UserRoles ON Roles.role_id = UserRoles.role_id WHERE UserRoles.username = ?';
    mysqlConn.query(query, [username], function(error, results) {
        if (error) {
            // Handle error...
            return res.status(500).send('Server Error');
        }
        const roles = results.map(row => row.role_name);

        if (policyDecisionPoint(roles, requestedResource)) {
            return next(); // User has access to the resource
        } else {
            return res.status(403).send('Access Denied'); // User does not have access
        }
    });
}

// Using the PEP middleware in our routes
app.use(policyEnforcementPoint);
//Data Classification
function classifyData(data) {
    // logic to classify data based on predefined keywords
    if (data.includes('confidential')) {
        return 'Confidential';
    } else if (data.includes('internal')) {
        return 'Internal';
    } else {
        return 'Public';
    }
}
function logDataAccess(action, user, dataClassification, data) {
    const logEntry = {
        timestamp: new Date().toISOString(),
        action: action,
        user: user,
        classification: dataClassification,
        dataPreview: data.substring(0, 100) 
    };
    console.log(JSON.stringify(logEntry));
}

  // Data loss prevention mechanism
  app.post('/api/data', (req, res) => {
    const data = req.body.data;
    const username = req.session.username || 'Guest'; 
  
    const dataClassification = classifyData(data);
    logDataAccess('data_submission', username, dataClassification, data);
  
    if (isDataLossPreventionEnabled && !isDataExfiltrationDetected(data)) {
        const encryptedData = encryptData(data);
        saveDataToDatabase(encryptedData);
        res.status(200).json({ message: 'Data saved successfully' });
    } else {
        res.status(403).json({ message: 'Data loss prevention triggered' });
    }
  });
  
app.get('/customer/dashboard', isAuthenticated, checkUserRole(['Customer']), function(req, res) {
    res.sendFile(__dirname + '/dashboard.html'); // Existing dashboard for customers
});

app.get('/employee/dashboard', isAuthenticated, checkUserRole(['Employee']), function(req, res) {
    res.sendFile(__dirname + '/employee.html'); // New dashboard for employees
});

//Create the local https server on port 3000. "localhost:3000"
/*https.createServer({
    key: fs.readFileSync('./certs/MyKey.key'),
    
    cert: fs.readFileSync('./certs/MyCertificate.crt')}, app).listen(3000);
//app.listen(3000);*/

app.get('/login', csrfProtection, (req, res) => {
    // CSRF token in the login form
    res.render('login.html', { csrfToken: req.csrfToken() });
  });
  
  app.post('/login', parseForm, csrfProtection, (req, res) => {
    // Process login form
  });

const options = {
    key: fs.readFileSync('localhost-key.pem'),
    cert: fs.readFileSync('localhost.pem'),
  };
  
  https.createServer(options, app).listen(3000, () => {
    console.log('Server is running on https://localhost:3000');
  });


