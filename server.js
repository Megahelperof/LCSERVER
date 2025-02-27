const express = require('express');
const cors = require('cors');
const admin = require('firebase-admin');
const fs = require('fs').promises;
const path = require('path');
const { parse } = require('date-fns');
const { v4: uuidv4 } = require('uuid');
require('dotenv').config();
const PORT = process.env.PORT || 3000;


// Middleware
const app = express();
// const app = express(); // Duplicate declaration removed
app.use(express.static('public'));
app.use(express.json()); // Parse JSON request bodies
app.use(cors()); // Enable CORS for all routes
app.options('*', cors()); // Handle preflight requests

// Sample POST endpoint
app.post('/api/data', (req, res) => {
  const data = req.body;
  console.log('Received data:', data);
  res.json({ 
    received: true, 
    data: data,
    message: 'Data received successfully!'
  });
});

// Firebase Admin SDK initialization
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

  admin.initializeApp({
    credential: admin.credential.cert(serviceAccount),
    storageBucket: "lcccdb-891ca.appspot.com",
  });

  console.log("✅ Firebase initialized successfully!");
} catch (error) {
  console.error("❌ Firebase initialization error:", error);
  process.exit(1);
}

const db = admin.firestore();
const bucket = admin.storage().bucket();
const dataFilePath = path.join(__dirname, 'studentData.json');

// Global variables
let startTime = '04:10';
let lateTime = '07:10';

// Utility functions
function getPhilippineTime() {
  return new Date().toLocaleString('en-US', { timeZone: 'Asia/Manila' });
}

function parseTime(timeString) {
  const [hours, minutes] = timeString.split(':').map(Number);
  return { hours, minutes };
}

function parseDateTime(dateTimeString) {
  dateTimeString = dateTimeString.replace(/\s*\([^)]*\)/, '').trim();
  const [datePart, timePart] = dateTimeString.split(', Time: ');

  if (!datePart || !timePart) {
    console.error(`Invalid date-time format: ${dateTimeString}`);
    return null;
  }

  const [year, month, day] = datePart.split('-').map(Number);
  const timeParts = timePart.split('_').filter(Boolean);

  if (timeParts.length < 4) {
    console.error(`Invalid time format: ${timePart}`);
    return null;
  }

  const [hourMinSec, period] = timeParts.slice(-2);
  const [hours, minutes, seconds] = hourMinSec.split(':').map(Number);
  const adjustedHours = period.toUpperCase() === 'PM' && hours !== 12 ? hours + 12 : hours;

  if (isNaN(year) || isNaN(month) || isNaN(day) || isNaN(hours) || isNaN(minutes) || isNaN(seconds)) {
    console.error(`Invalid date components: ${dateTimeString}`);
    return null;
  }

  return new Date(year, month - 1, day, adjustedHours, minutes, seconds);
}

function dateMatches(dateTimeString, targetDate) {
  const parsedDate = parseDateTime(dateTimeString);
  return parsedDate ? parsedDate.toISOString().split('T')[0] === targetDate : false;
}

// Authentication middleware
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

// Routes
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


    // Find the last activity on the given date
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

// Helper function to get the folder path for a student
function getStudentFolderPath(grade, section, studentNumber) {
  return `students/${grade}/${section}/${studentNumber}/`;
}

// Updated logStudentActivity function

async function logStudentActivity(studentNumber, fullName, logViolations = false) {
  const activityTime = getPhilippineTime();
  const formattedActivityTime = activityTime.replace(/[^\w\s]/gi, '_');
  const date = new Date(activityTime).toISOString().split('T')[0];

  // Find the correct folder path based on the student's grade and section
  let folderPath = null;
  let grade = null;
  let section = null;

  // Check for the main.txt file in all possible folders
  const possibleFolders = [
    `students/7/A/${studentNumber}/`,
    `students/7/B/${studentNumber}/`,
    `students/7/C/${studentNumber}/`,
    `students/7/D/${studentNumber}/`,
    `students/8/A/${studentNumber}/`,
    `students/8/B/${studentNumber}/`,
    `students/8/C/${studentNumber}/`,
    `students/8/D/${studentNumber}/`,
    `students/9/A/${studentNumber}/`,
    `students/9/B/${studentNumber}/`,
    `students/9/C/${studentNumber}/`,
    `students/9/D/${studentNumber}/`,
    `students/10/A/${studentNumber}/`,
    `students/10/B/${studentNumber}/`,
    `students/10/C/${studentNumber}/`,
    `students/10/D/${studentNumber}/`,
  ];

  for (const folder of possibleFolders) {
    const mainFilePath = `${folder}${studentNumber}_main.txt`;
    const [mainFileExists] = await bucket.file(mainFilePath).exists();

    if (mainFileExists) {
      folderPath = folder;
      // Read the student's grade and section from the main file
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

  const logFilePath = `${folderPath}${studentNumber}_activity.txt`;

  try {
    let isExit = false;
    let lateTag = '';
    let violationsTag = '';

    // Check for last activity
    const lastActivity = await getLastActivity(studentNumber, date);
    if (lastActivity) {
      const lastActivityTime = new Date(lastActivity.time);
      const currentTime = new Date(activityTime);
      const timeDiff = (currentTime - lastActivityTime) / (1000 * 60); // difference in minutes
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

    // Update Firestore
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

    // Update activity file in Firebase Storage
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
// Updated logStudentActivity function



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
    // Read existing content
    const [fileExists] = await bucket.file(filePath).exists();
    let content = '';
    if (fileExists) {
      const [fileContent] = await bucket.file(filePath).download();
      content = fileContent.toString('utf-8');
    }

    // Parse existing content
    const lines = content.split('\n');
    const headerLines = lines.slice(0, 4); // Assuming the first 4 lines are header information
    let lateEntries = lines.slice(4).filter(line => line.trim() !== '');

    // Add new entry if it's late
    if (newEntry.includes('(Late)')) {
      lateEntries.push(newEntry);
    }

    // Sort late entries by date
    lateEntries.sort((a, b) => {
      const dateA = new Date(a.split(', Time:')[0].split('Date: ')[1]);
      const dateB = new Date(b.split(', Time:')[0].split('Date: ')[1]);
      return dateB - dateA;
    });

    // Combine header and sorted late entries
    const updatedContent = [...headerLines, ...lateEntries].join('\n');

    // Upload updated content
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

// New endpoint to set late times
app.post('/api/setLateTimes', (req, res) => {
  const { newStartTime, newLateTime } = req.body;

  if (!newStartTime || !newLateTime) {
    return res.status(400).json({ success: false, message: 'Both start time and late time are required.' });
  }

  // Validate time format (HH:MM)
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
app.get('/api/search', async (req, res) => {
  const studentNumber = req.query.studentNumber;

  if (!studentNumber) {
    return res.status(400).json({ error: 'Student number is required' });
  }

  try {
    const studentDocRef = db.collection('students').doc(studentNumber);
    const studentDoc = await studentDocRef.get();

    if (studentDoc.exists) {
      const studentData = studentDoc.data();
      res.json({ fullName: studentData.fullName });
    } else {
      res.json({ error: 'Student not found' });
    }
  } catch (error) {
    console.error('Error fetching student data:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.post('/api/validate-token', async (req, res) => {
  const { token } = req.body;

  if (!token || token.length !== 4) {
    return res.status(400).json({ valid: false });
  }

  const filePath = `Token/${token}.txt`;

  try {
    const [fileExists] = await bucket.file(filePath).exists();
    return res.status(200).json({ valid: fileExists });
  } catch (error) {
    console.error('Error checking token:', error);
    return res.status(500).json({ valid: false });
  }
});

// Helper function to read student data
async function readStudentData() {
    try {
        const data = await fs.readFile(dataFilePath, 'utf8');
        return JSON.parse(data);
    } catch (error) {
        console.error('Error reading student data:', error);
        return {};
    }
}
// Helper function to write student data
async function writeStudentData(data) {
    try {
        await fs.writeFile(dataFilePath, JSON.stringify(data, null, 2));
    } catch (error) {
        console.error('Error writing student data:', error);
    }
}

app.post('/api/getStudentInfo', async (req, res) => {
  try {
      const { query } = req.body; // Can be studentNumber or fullName

      let studentDoc = null;

      if (!isNaN(query)) {
          // If the input is a number, search by studentNumber
          studentDoc = await db.collection('students').doc(query).get();
      } else {
          // If the input is a string, search by fullName
          const studentsRef = db.collection('students');
          const snapshot = await studentsRef.where('fullName', '==', query).get();
          if (!snapshot.empty) {
              studentDoc = snapshot.docs[0]; // Take the first matching document
          }
      }

      if (!studentDoc || !studentDoc.exists) {
          return res.json({ success: false, message: 'Student not found' });
      }

      const studentData = studentDoc.data();
      const studentNumber = studentData.studentNumber;

      // Fetch violations from Storage
      const filePath = `students/${studentNumber}/${studentNumber}violations.txt`;
      const [fileExists] = await bucket.file(filePath).exists();

      let lastViolations = 'None';
      if (fileExists) {
          const [content] = await bucket.file(filePath).download();
          const violations = content.toString('utf-8').split('\n').filter(Boolean);
          lastViolations = violations[violations.length - 1] || 'None';
      }

      res.json({
          success: true,
          studentInfo: {
              studentNumber,
              fullName: studentData.fullName,
              lastViolations,
              details: studentData.notice || 'No additional details'
          }
      });
  } catch (error) {
      console.error('Error fetching student data:', error);
      res.status(500).json({ success: false, message: 'Internal server error' });
  }
});


// Assuming Firebase Admin SDK is already initialized

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


// Fetch all notices
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

// Edit a notice
app.put('/admin/editNotice/:fileName', async (req, res) => {
    try {
        const { fileName } = req.params;
        const { newNotice } = req.body;

        if (!newNotice) {
            return res.status(400).json({ success: false, message: 'Missing new notice text' });
        }

        const file = bucket.file(fileName);
        const [exists] = await file.exists();
        if (!exists) {
            return res.status(404).json({ success: false, message: 'Notice not found' });
        }

        const currentDate = new Date().toISOString();
        const fileContent = `Date: ${currentDate}\nNotice: ${newNotice}`;

        await file.save(fileContent, {
            metadata: {
                contentType: 'text/plain',
            },
        });

        res.json({ success: true, message: 'Notice updated successfully' });
    } catch (error) {
        console.error('Error editing notice:', error);
        res.status(500).json({ success: false, message: 'Internal server error' });
    }
});

// Remove a notice
app.delete('/admin/removeNotice/:fileName', async (req, res) => {
    try {
        const { fileName } = req.params;
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

        // Fetch student data to get grade and section
        const studentRef = admin.firestore().collection('students').doc(studentNumber);
        const studentDoc = await studentRef.get();

        if (!studentDoc.exists) {
            return res.status(404).json({ success: false, message: 'Student not found' });
        }

        const studentData = studentDoc.data();
        const { grade, section } = studentData;

        // Create the correct folder path
        const folderPath = getStudentFolderPath(grade, section, studentNumber);
        const filePath = `${folderPath}${studentNumber}_violations.txt`;

        // Check if the file exists
        const [fileExists] = await bucket.file(filePath).exists();

        let currentContent = '';
        if (fileExists) {
            // If file exists, download its content
            const [content] = await bucket.file(filePath).download();
            currentContent = content.toString('utf-8');
        }

        // Format the new violation log entry
        const logEntry = `${date}: ${violations.join(', ')}${manualEntry ? ' (Manual Entry)' : ''}\n`;

        // Combine existing content with new log entry
        const updatedContent = currentContent + logEntry;

        // Upload the updated content back to Firebase Storage
        await bucket.file(filePath).save(updatedContent, {
            contentType: 'text/plain',
            metadata: {
                cacheControl: 'private, max-age=0'
            }
        });

        // Update the student's record in Firestore
        await studentRef.set({
            lastViolationDate: date,
            violationsCount: admin.firestore.FieldValue.increment(1)
        }, { merge: true });

        res.json({ success: true, message: 'Violations logged successfully' });
    } catch (error) {
        console.error('Error logging violations:', error);
        res.status(500).json({ success: false, message: 'Internal server error' });
    }
});
app.post('/api/logMultipleViolations', async (req, res) => {
    try {
        const { studentNumber, violations, date, manualEntry } = req.body;

        if (!studentNumber || !violations || violations.length === 0 || !date) {
            return res.status(400).json({ success: false, message: 'Missing required fields' });
        }

        const filePath = `students/${studentNumber}/${studentNumber}violations.txt`;

        // Check if the file exists
        const [fileExists] = await bucket.file(filePath).exists();

        let currentContent = '';
        if (fileExists) {
            // If file exists, download its content
            const [content] = await bucket.file(filePath).download();
            currentContent = content.toString('utf-8');
        }

        // Format the new violation log entry
        const logEntry = `${date}: ${violations.join(', ')}${manualEntry ? ' (Manual Entry)' : ''}\n`;

        // Combine existing content with new log entry
        const updatedContent = currentContent + logEntry;

        // Upload the updated content back to Firebase Storage
        await bucket.file(filePath).save(updatedContent, {
            contentType: 'text/plain',
            metadata: {
                cacheControl: 'private, max-age=0'
            }
        });

        // Update the student's record in Firestore
        const studentRef = admin.firestore().collection('students').doc(studentNumber);
        await studentRef.set({
            lastViolationDate: date,
            violationsCount: admin.firestore.FieldValue.increment(violations.length)
        }, { merge: true });

        res.json({ success: true, message: 'Violations logged successfully' });
    } catch (error) {
        console.error('Error logging violations:', error);
        res.status(500).json({ success: false, message: 'Internal server error' });
    }
});

app.post('/api/createStudentFolder', async (req, res) => {
  const { studentNumber, fullName, grade, section } = req.body;

  if (!studentNumber || !fullName || !grade || !section) {
    return res.status(400).send("studentNumber, fullName, grade, and section are required.");
  }

  try {
    const folderPath = getStudentFolderPath(grade, section, studentNumber);
    const fileName = `${studentNumber}_main.txt`;
    const fileContent = `Student Number: ${studentNumber}\nFull Name: ${fullName}\nGrade: ${grade}\nSection: ${section}\n`;

    const file = bucket.file(`${folderPath}${fileName}`);
    await file.save(fileContent, {
      metadata: {
        contentType: 'text/plain',
      }
    });

    // Create Firestore document for the student
    await db.collection('students').doc(studentNumber).set({
      studentNumber,
      fullName,
      grade,
      section
    });

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

    // Check entry times
    if (studentData.entryTime) {
      studentData.entryTime.forEach(entry => {
        if (dateMatches(entry, date)) {
          records.push(entry);
        }
      });
    }

    // Check exit times
    if (studentData.exitTime) {
      studentData.exitTime.forEach(exit => {
        if (dateMatches(exit, date)) {
          records.push(exit);
        }
      });
    }

    // Check violations
    if (studentData.violations) {
      studentData.violations.forEach(violation => {
        const violationDate = new Date(violation.split('T')[0]).toISOString().split('T')[0];
        if (violationDate === date) {
          records.push(`Violation: ${violation}`);
        }
      });
    }

    // Sort records by time
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


// Serve static files
app.use(express.static(path.join(__dirname, 'public')));
app.use('/admin', express.static(path.join(__dirname, 'admin')));


// Middleware to handle redirects from '/' to '/entrance'
app.use((req, res, next) => {
  if (req.path === '/') {
    res.redirect('/entrance');
  } else {
    next();
  }
});

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


// Define routes to serve HTML files
const routes = {
  '/settings': '../Admin/settings.html',
  '/dashboard': '../Admin/dashboard.html',
  '/notice': '../Admin/notice.html',
  '/manualviolation': '../Admin/manualviolation.html',
  '/UserCreate': '../Admin/UserCreate.html',
  '/studentsearch': '../Admin/studentsearch.html',
  '/searchdate': '../Admin/searchdate.html',
  '/usernotice': '../Admin/usernotice.html',
  '/active': '../Admin/active.html',
  '/login': '../Admin/AdminUser/login.html',
  '/home': 'index.html',
};


Object.entries(routes).forEach(([route, filePath]) => {
  app.get(route, (req, res) => {
    res.sendFile(path.join(__dirname, filePath));
  });
});

app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});


// Error handling middleware
app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).json({ 
    success: false, 
    message: 'Internal server error' 
  });
});