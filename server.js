const express = require('express');
const cors = require('cors');
const admin = require('firebase-admin');
const fs = require('fs').promises;
const path = require('path');
const { parse } = require('date-fns');
const { v4: uuidv4 } = require('uuid');
require('dotenv').config();
const PORT = process.env.PORT || 3000;
const app = express();

app.use(express.json());
app.use((req, res, next) => {
  const allowedOrigins = [
    'https://lcccdb-891ca.web.app',
    'https://lcccdb-891ca.firebaseapp.com',
    'http://localhost:5000',    // Firebase Emulator
    'http://127.0.0.1:5000',    // Explicit localhost
    'http://localhost:3000',    // Common React/Vite port
    'http://localhost:8080'     // Common static server port
  ];
  
  const origin = req.headers.origin;
  if (allowedOrigins.includes(origin)) {
    res.setHeader('Access-Control-Allow-Origin', origin);
    res.setHeader('Access-Control-Allow-Credentials', 'true');
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  }

  if (req.method === 'OPTIONS') {
    return res.status(200).end();
  }
  
  next();
});

try {
  if (!process.env.FIREBASE_PRIVATE_KEY) {
    throw new Error("FIREBASE_PRIVATE_KEY is missing from environment variables");
  }

const serviceAccount = {
  type: process.env.FIREBASE_TYPE || "",
  project_id: process.env.FIREBASE_PROJECT_ID || "",
  private_key_id: process.env.FIREBASE_PRIVATE_KEY_ID || "",
  private_key: (process.env.FIREBASE_PRIVATE_KEY || "").replace(/\\n/g, "\n"),
  client_email: process.env.FIREBASE_CLIENT_EMAIL || "",
  client_id: process.env.FIREBASE_CLIENT_ID || "",
  auth_uri: process.env.FIREBASE_AUTH_URI || "",
  token_uri: process.env.FIREBASE_TOKEN_URI || "",
  auth_provider_x509_cert_url: process.env.FIREBASE_AUTH_PROVIDER_X509_CERT_URL || "",
  client_x509_cert_url: process.env.FIREBASE_CLIENT_X509_CERT_URL || "",
  universe_domain: process.env.FIREBASE_UNIVERSE_DOMAIN || "",
};

if (!admin.apps.length) {
  admin.initializeApp({
    credential: admin.credential.cert(serviceAccount),
    storageBucket: "lcccdb-891ca.appspot.com",
  });
}

console.log("✅ Firebase initialized successfully!");

const storage = admin.storage();
const db = admin.firestore(); 
const bucket = admin.storage().bucket();
  app.locals.db = db;
  app.locals.bucket = bucket;

} catch (error) {
  console.error("❌ Firebase initialization error:", error);
  process.exit(1);
}

app.use(express.static(path.join(__dirname, 'public')));
app.use('/admin', express.static(path.join(__dirname, 'admin')));

const folderPaths = require('./possiblefolder.json');
const routes = {
  '/admin/settings': 'settings.html',
  '/admin/dashboard': 'dashboard.html',
  '/admin/notice': 'notice.html',
  '/admin/manualviolation': 'manualviolation.html',
  '/admin/UserCreate': 'UserCreate.html',
  '/admin/studentsearch': 'studentsearch.html',
  '/admin/searchdate': 'searchdate.html',
  '/admin/usernotice': 'usernotice.html',
  '/admin/active': 'active.html',
  '/admin/login': 'AdminUser/login.html',
};

console.log("Bucket initialized:", !!admin.storage().bucket());

app.post('/api/data', (req, res) => {
  const data = req.body;
  console.log('Received data:', data);
  res.json({ 
    received: true, 
    data: data,
    message: 'Data received successfully!'
  });
});

const dataFilePath = path.join(__dirname, 'studentData.json');

let startTime = '04:10';
let lateTime = '07:10';

function getPhilippineTime() {
  return new Date().toLocaleString('en-US', { timeZone: 'Asia/Manila' });
}

function parseTime(timeString) {
  const [hours, minutes] = timeString.split(':').map(Number);
  return { hours, minutes };
}

function formatTimestamp(date = new Date()) {
  return format(date, "MM_dd_yyyy_HH_mm_ss");
}
function parseDateTime(dateTimeString) {
  try {
  
    const cleanedString = dateTimeString
      .replace(/\s*\([^)]*\)/g, '') 
      .replace(/_/g, ' ')           
      .replace(/,?\s*Time:?\s*/i, ' ') 
      .trim();

    const patterns = [
      'MM dd yyyy h mm ss a',  
      'MM-dd-yyyy h:mm:ss a',  
      'yyyy MM dd h mm ss a',  
    ];

    for (const pattern of patterns) {
      try {
        const parsedDate = parse(cleanedString, pattern, new Date());
        if (!isNaN(parsedDate.getTime())) {
          return parsedDate;
        }
      } catch (patternError) {

      }
    }

    const dateParts = cleanedString.match(/(\d+)/g) || [];
    if (dateParts.length >= 6) {
      const [month, day, year, hour, minute, second] = dateParts;
      const period = cleanedString.includes('PM') ? 'PM' : 'AM';
      const adjustedHours = period === 'PM' && hour < 12 ? 
        parseInt(hour) + 12 : 
        parseInt(hour);

      return new Date(
        parseInt(year),
        parseInt(month) - 1,
        parseInt(day),
        adjustedHours,
        parseInt(minute),
        parseInt(second)
      );
    }

    console.error(`Unrecognized date-time format: ${dateTimeString}`);
    return null;
  } catch (error) {
    console.error(`Error parsing date-time: ${dateTimeString}`, error);
    return null;
  }
}

app.get('/api/index.js', (req, res) => {
  res.setHeader('Content-Type', 'application/javascript');
  res.sendFile(path.join(__dirname, 'public', 'index.js')); 
});

function dateMatches(dateTimeString, targetDate) {
  const parsedDate = parseDateTime(dateTimeString);
  return parsedDate ? parsedDate.toISOString().split('T')[0] === targetDate : false;
}

async function authenticate(req, res, next) {
  try {
    const authToken = req.cookies.authToken;
    if (!authToken) {
      return res.redirect('/login.html');
    }

    const decodedToken = await admin.auth().verifyIdToken(authToken);
    req.user = decodedToken;
    next();
  } catch (error) {
    console.error('Authentication error:', error);
    res.redirect('/login.html');
  }
}

app.post('/api/validate', (req, res) => {
  const { token } = req.body;
  res.json({ 
    valid: token === "1234",
    message: token === "1234" ? "Token is valid!" : "Invalid token!" 
  });
});

async function getLastActivity(studentNumber, date) {
  const studentDocRef = db.collection('students').doc(studentNumber);
  const studentDoc = await studentDocRef.get();
  const studentData = studentDoc.exists ? studentDoc.data() : null;

  if (studentData) {
    const entryTimes = studentData.entryTime || [];
    const exitTimes = studentData.exitTime || [];

    for (let i = entryTimes.length - 1; i >= 0; i--) {
      if (dateMatches(entryTimes[i], date)) {
        return { time: entryTimes[i], type: 'entry' };
      }
    }

    for (let i = exitTimes.length - 1; i >= 0; i--) {
      if (dateMatches(exitTimes[i], date)) {
        return { time: exitTimes[i], type: 'exit' };
      }
    }
  }

  return null;
}

function isLate(entryTime) {
  const time = new Date(entryTime);
  const { hours: startHours, minutes: startMinutes } = parseTime(startTime);
  const { hours: lateHours, minutes: lateMinutes } = parseTime(lateTime);

  const startThreshold = new Date(time);
  startThreshold.setHours(startHours, startMinutes, 0, 0);

  const lateThreshold = new Date(time);
  lateThreshold.setHours(lateHours, lateMinutes, 0, 0);

  return time < startThreshold || time > lateThreshold;
}

function getStudentFolderPath(grade, section, studentNumber) {
  return `students/${grade}/${section}/${studentNumber}/`;
}

async function logStudentActivity(studentNumber, fullName, logViolations = false) {
  const activityTime = getPhilippineTime();
  const formattedActivityTime = activityTime.replace(/[^\w\s]/gi, '_');
  const date = new Date(activityTime).toISOString().split('T')[0];

  let folderPath = null;
  let grade = null;
  let section = null;

  const possibleFolders = folderPaths.possibleFolders;

  for (const folder of possibleFolders) {
    const mainFilePath = `${folder}${studentNumber}/${studentNumber}_main.txt`;
    const [mainFileExists] = await bucket.file(mainFilePath).exists();

    if (mainFileExists) {
      folderPath = folder;
      const [content] = await bucket.file(mainFilePath).download();
      const fileContent = content.toString('utf-8');
      const lines = fileContent.split('\n');

      for (const line of lines) {
        if (line.startsWith('Grade:')) {
          grade = line.split(':')[1].trim();
        } else if (line.startsWith('Section:')) {
          section = line.split(':')[1].trim();
        }
      }
      console.log(`Main folder found at: ${folderPath}`);
      break;
    }
  }

  if (!folderPath) {
    console.error(`Main folder not found for student ${studentNumber}`);
    return { isExit: false, activityLabel: null };
  }

  const logFilePath = `${folderPath}${studentNumber}/${studentNumber}_activity.txt`;

  try {
    let isExit = false;
    let lateTag = '';
    let violationsTag = '';

    const lastActivity = await getLastActivity(studentNumber, date);
    if (lastActivity) {
      const lastActivityTime = new Date(lastActivity.time);
      const currentTime = new Date(activityTime);
      const timeDiff = (currentTime - lastActivityTime) / (1000 * 60); 
      const lastActivityDate = lastActivityTime.toISOString().split('T')[0];

      if (lastActivityDate === date) {
        if (lastActivity.type === 'entry' && timeDiff >= 1) {
          isExit = true;
        } else if (timeDiff < 1) {
          console.log(`Cooldown period not met for ${fullName} (${studentNumber}). Skipping log.`);
          return { isExit: false, activityLabel: null };
        }
      }
    }

    if (!isExit) {
      lateTag = isLate(activityTime) ? ' (Late)' : '';
    }

    if (logViolations) {
      violationsTag = ' (Violations)';
    }

    const activityType = isExit ? 'exitTime' : 'entryTime';
    const studentDocRef = db.collection('students').doc(studentNumber);
    const studentDoc = await studentDocRef.get();
    const studentData = studentDoc.exists ? studentDoc.data() : null;

    if (studentData) {
      await studentDocRef.update({
        [activityType]: admin.firestore.FieldValue.arrayUnion(`${formattedActivityTime}${lateTag}${violationsTag}`),
        lastActivity: { time: activityTime, type: isExit ? 'exit' : 'entry' },
        grade: grade,
        section: section
      });
    } else {
      await studentDocRef.set({
        studentNumber: studentNumber,
        fullName: fullName,
        grade: grade,
        section: section,
        [activityType]: [`${formattedActivityTime}${lateTag}${violationsTag}`],
        lastActivity: { time: activityTime, type: 'entry' }
      });
    }

    const activityLabel = isExit ? 'Exit' : 'Entry';
    const activityFileContent = `${activityLabel} Date: ${date}, Time: ${formattedActivityTime}${lateTag}${violationsTag}\n`;
    await appendToFirebaseFile(logFilePath, activityFileContent);

    console.log(`Logged ${activityLabel.toLowerCase()} for ${fullName} (${studentNumber}) at ${formattedActivityTime}${lateTag}${violationsTag}`);
    return { isExit, activityLabel, grade, section };
  } catch (error) {
    console.error(`Error in logStudentActivity:`, error);
    throw error;
  }
}

async function appendToFirebaseFile(filePath, content) {
  try {
    const file = bucket.file(filePath);
    const [exists] = await file.exists();

    if (!exists) {
      await file.save(content);
    } else {
      const [currentContent] = await file.download();
      const updatedContent = currentContent.toString() + content;
      await file.save(updatedContent);
    }

    console.log(`Updated file: ${filePath}`);
  } catch (error) {
    console.error(`Error appending to Firebase file ${filePath}:`, error);
    throw error;
  }
}

async function updateMainTxtWithLateEntries(studentNumber, grade, section, newEntry) {
  const folderPath = getStudentFolderPath(grade, section, studentNumber);
  const filePath = `${folderPath}${studentNumber}_main.txt`;

  try {
    const [fileExists] = await bucket.file(filePath).exists();
    let content = '';
    if (fileExists) {
      const [fileContent] = await bucket.file(filePath).download();
      content = fileContent.toString('utf-8');
    }

    const lines = content.split('\n');
    const headerLines = lines.slice(0, 4); 
    let lateEntries = lines.slice(4).filter(line => line.trim() !== '');

    if (newEntry.includes('(Late)')) {
      lateEntries.push(newEntry);
    }

    lateEntries.sort((a, b) => {
      const dateA = new Date(a.split(', Time:')[0].split('Date: ')[1]);
      const dateB = new Date(b.split(', Time:')[0].split('Date: ')[1]);
      return dateB - dateA;
    });

    const updatedContent = [...headerLines, ...lateEntries].join('\n');

    await bucket.file(filePath).save(updatedContent, {
      contentType: 'text/plain',
      metadata: {
        cacheControl: 'private, max-age=0'
      }
    });

    console.log(`Updated main.txt for student ${studentNumber} with late entries`);
  } catch (error) {
    console.error(`Error updating main.txt for student ${studentNumber}:`, error);
  }
}

app.post('/api/setLateTimes', (req, res) => {
  const { newStartTime, newLateTime } = req.body;

  if (!newStartTime || !newLateTime) {
    return res.status(400).json({ success: false, message: 'Both start time and late time are required.' });
  }

  const timeRegex = /^([01]\d|2[0-3]):([0-5]\d)$/;
  if (!timeRegex.test(newStartTime) || !timeRegex.test(newLateTime)) {
    return res.status(400).json({ success: false, message: 'Invalid time format. Use HH:MM.' });
  }

  startTime = newStartTime;
  lateTime = newLateTime;

  res.json({
    success: true,
    message: 'Late times updated successfully.',
    startTime: startTime,
    lateTime: lateTime
  });
});

app.post('/api/logActivity', async (req, res) => {
  const { studentNumber } = req.body;

  if (!studentNumber) {
    return res.status(400).json({ success: false, message: 'Student number is required.' });
  }

  try {
    const studentDocRef = db.collection('students').doc(studentNumber);
    const studentDoc = await studentDocRef.get();

    if (!studentDoc.exists) {
      return res.status(404).json({ success: false, message: 'Student not found.' });
    }

    const studentData = studentDoc.data();
    const { isExit, activityLabel } = await logStudentActivity(studentNumber, studentData.fullName);

    res.json({
      success: true,
      fullName: studentData.fullName,
      message: `${activityLabel} logged successfully.`,
      isExit: isExit
    });
  } catch (error) {
    console.error('Error logging activity:', error);
    res.status(500).json({
      success: false,
      message: 'Internal server error. Please try again later.'
    });
  }
});

app.post('/api/logEntrance', async (req, res) => {
  const { studentNumber, violations } = req.body;

  if (!studentNumber) {
    return res.status(400).json({ success: false, message: 'Student number is required.' });
  }

  try {
    const studentDocRef = db.collection('students').doc(studentNumber);
    const studentDoc = await studentDocRef.get();

    if (!studentDoc.exists) {
      return res.status(404).json({ success: false, message: 'Student not found.' });
    }

    const studentData = studentDoc.data();
    const { isExit, activityLabel } = await logStudentActivity(studentNumber, studentData.fullName, !!violations);

    let message = `${activityLabel} logged successfully.`;
    if (violations) {
      message += ' Violations recorded.';
    }

    res.json({
      success: true,
      fullName: studentData.fullName,
      message: message,
      isExit: isExit
    });
  } catch (error) {
    console.error('Error logging entrance:', error);
    res.status(500).json({
      success: false,
      message: 'Internal server error. Please try again later.'
    });
  }
});
app.get('/api/debugStudent/:studentNumber', async (req, res) => {
  const studentNumber = req.params.studentNumber;
  const studentDocRef = db.collection('students').doc(studentNumber);
  const studentDoc = await studentDocRef.get();

  if (!studentDoc.exists) {
      return res.json({ success: false, message: `Student ${studentNumber} not found in Firestore` });
  }

  res.json({ success: true, studentData: studentDoc.data() });
});

app.post('/api/validate-token', async (req, res) => {
  try {
    const { token } = req.body;
    
    if (!token || token.length !== 4) {
      return res.status(400).json({ valid: false });
    }

    const bucket = app.locals.bucket; // ✅ Use app.locals.bucket instead
    if (!bucket) {
      console.error("❌ Firebase Storage bucket is not initialized.");
      return res.status(500).json({ valid: false, message: "Internal server error" });
    }

    const filePath = `Token/${token}.txt`;
    const [fileExists] = await bucket.file(filePath).exists();
    
    return res.status(200).json({ valid: fileExists });
  } catch (error) {
    console.error('Error checking token:', error);
    return res.status(500).json({ valid: false });
  }
});


async function readStudentData() {
    try {
        const data = await fs.readFile(dataFilePath, 'utf8');
        return JSON.parse(data);
    } catch (error) {
        console.error('Error reading student data:', error);
        return {};
    }
}

async function writeStudentData(data) {
    try {
        await fs.writeFile(dataFilePath, JSON.stringify(data, null, 2));
    } catch (error) {
        console.error('Error writing student data:', error);
    }
}

app.post('/api/getStudentInfo', async (req, res) => {
  try {
    const { query } = req.body;
    const db = admin.firestore(); // Ensure Firestore is correctly initialized

    if (!query || typeof query !== "string") {
      return res.status(400).json({ success: false, message: "Invalid query parameter" });
    }

    console.log("🔍 Searching for student:", query);

    let studentDoc = null;
    let studentNumber = null;
    let studentFolder = null;
    const cleanedQuery = query.replace(/-/g, ''); // Remove hyphens for consistency

    // 🔹 Try searching by student number
    if (!isNaN(cleanedQuery)) {
      studentDoc = await db.collection('students').doc(cleanedQuery).get();
      if (studentDoc.exists) {
        studentNumber = cleanedQuery;
      }
    } else {
      // 🔹 Try searching by full name
      const snapshot = await db.collection('students')
        .where('fullName', '==', query)
        .limit(1)
        .get();

      if (!snapshot.empty) {
        studentDoc = snapshot.docs[0];
        studentNumber = studentDoc.id;
      } else {
        // 🔹 If not found, check Firebase Storage for student records
        for (const folder of folderPaths.possibleFolders) {
          const [files] = await bucket.getFiles({ prefix: folder });
          for (const file of files) {
            if (file.name.endsWith('_main.txt')) {
              const [content] = await file.download();
              const fileContent = content.toString('utf-8');
              const lines = fileContent.split("\n");
              let foundName = "", foundNumber = "";

              for (const line of lines) {
                if (line.startsWith("Full Name:")) foundName = line.split(":")[1].trim();
                if (line.startsWith("Student Number:")) foundNumber = line.split(":")[1].trim();
              }

              if (foundName.toLowerCase() === query.toLowerCase()) {
                studentNumber = foundNumber;
                studentFolder = folder;
                break;
              }
            }
          }
          if (studentNumber) break;
        }

        if (studentNumber) {
          studentDoc = await db.collection('students').doc(studentNumber).get();
        }
      }
    }

    // 🔹 If no student record was found
    if (!studentDoc?.exists) {
      console.warn(`❌ Student not found: ${query}`);
      return res.json({ success: false, message: "Student not found" });
    }

    const studentData = studentDoc.data();
    let lastViolations = "None";
    let noticeDetails = "No additional details";

    // 🔹 Check for violations file
    if (studentFolder) {
      const violationPath = `${studentFolder}${studentNumber}/${studentNumber}_violations.txt`;
      const [violationExists] = await bucket.file(violationPath).exists();

      if (violationExists) {
        const [content] = await bucket.file(violationPath).download();
        const violations = content.toString('utf-8').split('\n').filter(Boolean);
        lastViolations = violations.length ? violations[violations.length - 1] : "None";
      }
    }

    // 🔹 Check for student notices in Firebase Storage
    const [noticeFiles] = await bucket.getFiles({ prefix: `notice/${studentNumber}notice_` });

    if (noticeFiles.length > 0) {
      const sortedNotices = noticeFiles.sort((a, b) => 
        b.metadata.updated.localeCompare(a.metadata.updated)
      );

      try {
        const [latestNotice] = await sortedNotices[0].download();
        noticeDetails = latestNotice.toString('utf-8');
      } catch (error) {
        console.error("⚠️ Error loading notice:", error);
      }
    }

    console.log(`✅ Student found: ${studentData.fullName} (${studentNumber})`);
    res.json({
      success: true,
      studentInfo: {
        studentNumber,
        fullName: studentData.fullName,
        grade: studentData.grade,
        section: studentData.section,
        lastViolations,
        details: noticeDetails,
      },
    });

  } catch (error) {
    console.error("❌ Error fetching student info:", error);
    res.status(500).json({ success: false, message: "Internal server error" });
  }
});


app.post('/admin/submitNotice', async (req, res) => {
    try {
        const { studentNumber, noticeText } = req.body;

        if (!studentNumber || !noticeText) {
            return res.status(400).json({ success: false, message: 'Missing required fields' });
        }

        const bucket = admin.storage().bucket();
        const fileName = `notice/${studentNumber}notice_${uuidv4()}.txt`;
        const file = bucket.file(fileName);

        const currentDate = new Date().toISOString();
        const fileContent = `Date: ${currentDate}\nNotice: ${noticeText}`;

        await file.save(fileContent, {
            metadata: {
                contentType: 'text/plain',
            },
        });

        res.json({ success: true, message: 'Notice submitted successfully' });
    } catch (error) {
        console.error('Error submitting notice:', error);
        res.status(500).json({ success: false, message: 'Internal server error' });
    }
});

app.get('/admin/notices', async (req, res) => {
    try {
        const [files] = await bucket.getFiles({ prefix: 'notice/' });
        const notices = await Promise.all(files.map(async (file) => {
            const [content] = await file.download();
            return {
                fileName: file.name,
                content: content.toString('utf-8'),
                studentNumber: file.name.split('notice_')[0].replace('notice/', '')
            };
        }));
        res.json({ success: true, notices });
    } catch (error) {
        console.error('Error fetching notices:', error);
        res.status(500).json({ success: false, message: 'Internal server error' });
    }
});

async function updateNotice() {
  const fileName = document.getElementById('currentFileName').value;
  const newText = document.getElementById('newNoticeText').value;
  
  try {
      const response = await fetch(`/admin/editNotice/${fileName}`, {
          method: 'PUT',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ newNotice: newText })
      });
      
      if (response.ok) {
          loadAllNotices(); 
          document.getElementById('editNoticePopup').style.display = 'none';
      }
  } catch (error) {
      console.error('Error updating notice:', error);
  }
}

app.delete('/admin/removeNotice/:fileName(*)', async (req, res) => { 
  try {
      const fileName = req.params.fileName; 
      const file = bucket.file(fileName);

      const [exists] = await file.exists();
      if (!exists) {
          return res.status(404).json({ success: false, message: 'Notice not found' });
      }

      await file.delete();
      res.json({ success: true, message: 'Notice removed successfully' });
  } catch (error) {
      console.error('Error removing notice:', error);
      res.status(500).json({ success: false, message: 'Internal server error' });
  }
});


app.post('/api/validateMainBarcode', (req, res) => {
  const { studentNumber } = req.body;

  if (studentNumber && typeof studentNumber === 'string') {
    res.json({ success: true });
  } else {
    res.json({ success: false });
  }
});

app.post('/api/logViolation', async (req, res) => {
  try {
    const { studentNumber, violations, date, manualEntry } = req.body;

    if (!studentNumber || !violations || !date) {
      return res.status(400).json({ success: false, message: 'Missing required fields' });
    }

    const studentRef = db.collection('students').doc(studentNumber);
    const studentDoc = await studentRef.get();

    if (!studentDoc.exists) {
      return res.status(404).json({ success: false, message: 'Student not found' });
    }

    const studentData = studentDoc.data();

    let studentFolder = null;
    for (const folder of folderPaths.possibleFolders) {
      const mainFilePath = `${folder}${studentNumber}/${studentNumber}_main.txt`;
      const [mainFileExists] = await bucket.file(mainFilePath).exists();

      if (mainFileExists) {
        studentFolder = folder;
        break;
      }
    }

    if (!studentFolder) {
      return res.status(500).json({ success: false, message: 'Could not find the student’s folder.' });
    }

    const filePath = `${studentFolder}${studentNumber}/${studentNumber}_violations.txt`;

    const [fileExists] = await bucket.file(filePath).exists();
    let currentContent = '';

    if (fileExists) {
      const [content] = await bucket.file(filePath).download();
      currentContent = content.toString('utf-8');
    }

    const logEntry = `${date}: ${violations.join(', ')}${manualEntry ? ' (Manual Entry)' : ''}\n`;
    const updatedContent = currentContent + logEntry;

    await bucket.file(filePath).save(updatedContent, {
      contentType: 'text/plain',
      metadata: { cacheControl: 'private, max-age=0' },
    });

    await studentRef.set({
      lastViolationDate: date,
      violationsCount: admin.firestore.FieldValue.increment(1),
    }, { merge: true });

    res.json({ success: true, message: 'Violation logged successfully' });
  } catch (error) {
    console.error('❌ Error logging violation:', error);
    res.status(500).json({ success: false, message: 'Internal server error' });
  }
});

app.post('/api/logMultipleViolations', async (req, res) => {
  try {
    const { studentNumber, violations, date, manualEntry } = req.body;

    if (!studentNumber || !violations || violations.length === 0 || !date) {
      return res.status(400).json({ success: false, message: 'Missing required fields' });
    }

    const studentRef = db.collection('students').doc(studentNumber);
    const studentDoc = await studentRef.get();

    if (!studentDoc.exists) {
      return res.status(404).json({ success: false, message: 'Student not found' });
    }

    const studentData = studentDoc.data();


    let studentFolder = null;
    for (const folder of folderPaths.possibleFolders) {
      const mainFilePath = `${folder}${studentNumber}/${studentNumber}_main.txt`;
      const [mainFileExists] = await bucket.file(mainFilePath).exists();

      if (mainFileExists) {
        studentFolder = folder;
        break;
      }
    }

    if (!studentFolder) {
      return res.status(500).json({ success: false, message: 'Could not find the student’s folder.' });
    }

    const filePath = `${studentFolder}${studentNumber}/${studentNumber}_violations.txt`;

    const [fileExists] = await bucket.file(filePath).exists();
    let currentContent = '';

    if (fileExists) {
      const [content] = await bucket.file(filePath).download();
      currentContent = content.toString('utf-8');
    }


    const logEntry = `${date}: ${violations.join(', ')}${manualEntry ? ' (Manual Entry)' : ''}\n`;
    const updatedContent = currentContent + logEntry;

    await bucket.file(filePath).save(updatedContent, {
      contentType: 'text/plain',
      metadata: { cacheControl: 'private, max-age=0' },
    });


    await studentRef.set({
      lastViolationDate: date,
      violationsCount: admin.firestore.FieldValue.increment(violations.length),
    }, { merge: true });

    res.json({ success: true, message: 'Multiple violations logged successfully' });
  } catch (error) {
    console.error('❌ Error logging multiple violations:', error);
    res.status(500).json({ success: false, message: 'Internal server error' });
  }
});

app.post('/api/createStudentFolder', async (req, res) => {
  const { studentNumber, fullName, grade, section } = req.body;

  if (!studentNumber || !fullName || !grade || !section) {
    return res.status(400).send("Student number, full name, grade, and section are required.");
  }

  try {
    const folderPath = getStudentFolderPath(grade, section, studentNumber);

    if (!folderPath) {
      return res.status(500).json({ success: false, message: 'Could not find a suitable folder.' });
    }

    const fileName = `${studentNumber}_main.txt`;
    const fileContent = `Student Number: ${studentNumber}\nFull Name: ${fullName}\nGrade: ${grade}\nSection: ${section}\n`;

    const file = bucket.file(`${folderPath}${fileName}`);
    await file.save(fileContent, {
      metadata: { contentType: 'text/plain' },
    });

    await db.collection('students').doc(studentNumber).set({ studentNumber, fullName, grade, section });

    console.log(`Folder and file created for student number: ${studentNumber}`);
    res.status(200).send(`Folder and file created successfully for ${studentNumber}.`);

  } catch (error) {
    console.error("Error creating folder or file:", error);
    res.status(500).send("Error creating folder or file.");
  }
});

app.post('/api/getStudentRecords', async (req, res) => {
  const { studentNumber, date } = req.body;

  if (!studentNumber || !date) {
    return res.status(400).json({ success: false, message: 'Student number and date are required' });
  }

  try {
    const studentRef = db.collection('students').doc(studentNumber);
    const studentDoc = await studentRef.get();

    if (!studentDoc.exists) {
      return res.status(404).json({ success: false, message: 'Student not found' });
    }

    const studentData = studentDoc.data();
    const records = [];


    if (studentData.entryTime) {
      studentData.entryTime.forEach(entry => {
        if (dateMatches(entry, date)) {
          records.push(entry);
        }
      });
    }

    if (studentData.exitTime) {
      studentData.exitTime.forEach(exit => {
        if (dateMatches(exit, date)) {
          records.push(exit);
        }
      });
    }

    if (studentData.violations) {
      studentData.violations.forEach(violation => {
        const violationDate = new Date(violation.split('T')[0]).toISOString().split('T')[0];
        if (violationDate === date) {
          records.push(`Violation: ${violation}`);
        }
      });
    }

    records.sort((a, b) => {
      const timeA = parseDateTime(a.includes('Violation') ? a.split(': ')[1] : a);
      const timeB = parseDateTime(b.includes('Violation') ? b.split(': ')[1] : b);
      return timeA - timeB;
    });

    res.json({ success: true, records });
  } catch (error) {
    console.error('Error fetching student records:', error);
    res.status(500).json({ success: false, message: 'Internal server error' });
  }
});


app.post('/api/getViolationsSummary', async (req, res) => {
  const { studentNumber } = req.body;

  if (!studentNumber) {
    return res.status(400).json({ success: false, message: 'Student number is required' });
  }

  try {
    const studentRef = db.collection('students').doc(studentNumber);
    const studentDoc = await studentRef.get();

    if (!studentDoc.exists) {
      return res.json({ success: true, violations: {} });
    }

    const studentData = studentDoc.data();
    const violationsSummary = {};

    if (studentData.violations) {
      studentData.violations.forEach(violation => {
        const [dateTime, violationTypes] = violation.split(': ');
        const types = violationTypes.split(', ');
        types.forEach(type => {
          if (!violationsSummary[type]) {
            violationsSummary[type] = { count: 0, dates: [] };
          }
          violationsSummary[type].count++;
          violationsSummary[type].dates.push(dateTime.split('T')[0]);
        });
      });
    }

    res.json({ success: true, violations: violationsSummary });
  } catch (error) {
    console.error('Error fetching violations summary:', error);
    res.status(500).json({ success: false, message: 'Internal server error' });
  }
});app.post('/api/logClientConsole', (req, res) => {
  const { log } = req.body;

  if (log) {
    console.log(`Client Console Log: ${log}`);
    res.status(200).send('Log received');
  } else {
    res.status(400).send('No log provided');
  }
});

app.get('/', (req, res) => {
  res.redirect('/entrance');
});

async function authenticateAdmin(req, res, next) {
  try {

    const isShy = req.headers.shy === "shy";

    if (isShy) {
      console.log("🟢 LocalStorage 'shy=shy' detected. Granting Owner (Role 1).");
      req.user = { role: 1 }; 
      return next();
    }

    const authToken = req.headers.authorization?.split("Bearer ")[1];

    if (!authToken) {
      return res.status(401).json({ success: false, message: "Unauthorized: No token provided" });
    }

    const decodedToken = await admin.auth().verifyIdToken(authToken);
    const studentNumber = decodedToken.uid;

 
    const adminRef = db.collection("Admin").doc("AdminUser").collection(studentNumber).doc("info");
    const adminDoc = await adminRef.get();

    if (!adminDoc.exists) {
      return res.status(403).json({ success: false, message: "Forbidden: No access" });
    }

    const role = adminDoc.data().role;

    if (role === 4) {
      return res.status(403).json({ success: false, message: "Forbidden: No access" });
    }

    req.user = { ...decodedToken, role }; 
    next();
  } catch (error) {
    console.error("Authentication Error:", error);
    return res.status(403).json({ success: false, message: "Invalid or expired token" });
  }
}



(async () => {
    try {
        await fs.access(dataFilePath);
    } catch {
        const initialData = {
            "23-0199": {
                studentNumber: "23-0199",
                fullName: "Shyron Dwight R. Loveres",
                violations: []
            }
        };
        await writeStudentData(initialData);
        console.log('Initial student data created.');
    }
})();

Object.entries(routes).forEach(([route, file]) => {
  app.get(route, authenticateAdmin, (req, res) => { 
      res.sendFile(path.join(__dirname, 'admin', file));
  });
});

app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});

app.use((req, res, next) => {
  console.log(`Requested URL: ${req.url}`);
  next();
});

app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).json({ 
    success: false, 
    message: 'Internal server error' 
  });
});