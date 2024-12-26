const express = require('express');
const session = require('express-session');
const mysql = require('mysql2');
const multer = require('multer');
const cors = require('cors');
const sharp = require('sharp');
const { createCanvas, loadImage } = require('canvas');
const bcrypt = require('bcrypt');
const path = require('path');
const bodyParser = require('body-parser');
const saltRounds = 10;
require('dotenv').config(); // โหลดค่า environment จากไฟล์ .env

const app = express();

const PORT = process.env.PORT || 3001; // ใช้ port 3001
app.use(cors()); // เปิดใช้งาน CORS
app.use(bodyParser.json());
app.use(session({
  secret: 'Admin-2533',
  resave: false,               // ไม่ต้อง resave session ทุกครั้ง
  saveUninitialized: true,     // บันทึก session ทันทีที่มีการเริ่มต้น
  cookie: { secure: false }    // secure เป็น false หากไม่ได้ใช้ https
}));


// การตั้งค่าการเชื่อมต่อฐานข้อมูล MySQL
const connection = mysql.createPool({
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
});

const db = connection.promise();

const htmlPath = 'D:/testuploadimage/Html_';

// การตั้งค่า middleware
app.use(express.json());
app.use(express.static(path.join(__dirname, 'Html_')));
app.use(express.static(htmlPath));
app.use(express.urlencoded({ extended: true }));



// การตั้งค่า multer สำหรับอัปโหลดไฟล์
const storage = multer.memoryStorage(); // เก็บไฟล์ใน memory
const upload = multer({
  storage,
  fileFilter: (req, file, cb) => {
    // ตรวจสอบว่าไฟล์เป็น png, jpeg หรือ webp เท่านั้น
    const fileTypes = /jpeg|png|webp|jpg/;
    const extname = fileTypes.test(path.extname(file.originalname).toLowerCase());
    const mimeType = fileTypes.test(file.mimetype);

    if (extname && mimeType) {
      return cb(null, true);
    } else {
      cb(new Error('กรุณาอัปโหลดไฟล์ที่เป็นรูปภาพประเภท png, jpeg, หรือ webp เท่านั้น'));
    }
  },
}).single('image'); // ใช้ชื่อฟิลด์ 'image' ในการรับไฟล์

// เส้นทางสำหรับอัปโหลดไฟล์
app.post('/api/upload', upload, async (req, res) => {
  try {
    const { category, name, decorations_type } = req.body;
    const image = req.file.buffer;

    if (!image) {
      return res.status(400).json({ error: 'กรุณาอัปโหลดไฟล์ภาพ' });
    }

    if (!category || !name || !decorations_type) {
      return res.status(400).json({ error: 'กรุณาระบุหมวดหมู่, ชื่อ, และประเภทของตกแต่ง' });
    }
    // บันทึกข้อมูลลงในฐานข้อมูล
    const [rows] = await db.execute(
      'INSERT INTO images (category, name, image, decorations_type) VALUES (?, ?, ?, ?)',
      [category, name, image, decorations_type] // ส่งไฟล์ภาพในรูปแบบ Buffer
    );

    res.status(200).json({ message: 'อัปโหลดสำเร็จ!', id: rows.insertId });
  } catch (error) {
    console.error('Error:', error);
    res.status(500).json({ error: 'เกิดข้อผิดพลาดในการอัปโหลด' });
  }
});

// เส้นทางสำหรับดึงข้อมูลทั้งหมดจากฐานข้อมูล
app.get('/api/images', async (req, res) => {
  try {
    const [rows] = await db.execute('SELECT * FROM images');
    const imagesWithBase64 = rows.map(image => ({
      ...image,
      image: image.image ? image.image.toString('base64') : null // แปลง Buffer เป็น Base64
    }));
    res.status(200).json(imagesWithBase64);
  } catch (error) {
    console.error('Error:', error);
    res.status(500).json({ error: 'ไม่สามารถดึงข้อมูลจากฐานข้อมูลได้' });
  }
});

app.get('/api/images/selection/:id', async (req, res) => {
  try {
    const { id } = req.params;
    const category = 'example';  // กำหนด category ที่ต้องการให้ดึง
    // ดึงข้อมูลจากฐานข้อมูล
    const [rows] = await db.execute('SELECT image FROM images WHERE id = ? AND category = ?', [id,category]);


    if (rows.length > 0) {
      const image = rows[0].image; // ข้อมูลภาพในฐานข้อมูล (BLOB)

      // แปลง BLOB เป็น base64 และส่งให้ frontend
      const base64Image = Buffer.from(image).toString('base64');
      res.json({ status: 'OK', image: base64Image });
    } else {
      res.status(404).json({ status: 'error', message: 'ไม่พบภาพนี้' });
    }
  } catch (error) {
    console.error('Error:', error);
    res.status(500).json({ status: 'error', message: 'เกิดข้อผิดพลาดในการดึงภาพ' });
  }
});

app.get('/api/images/selection/:id/:category', async (req, res) => {
  try {
    const { id, category } = req.params; // ดึง id และ category จาก URL params
    // ดึงข้อมูลจากฐานข้อมูลตาม id และ category ที่รับเข้ามา
    const [rows] = await db.execute('SELECT image FROM images WHERE id = ? AND category = ?', [id, category]);

    if (rows.length > 0) {
      const image = rows[0].image; // ข้อมูลภาพในฐานข้อมูล (BLOB)

      // แปลง BLOB เป็น base64 และส่งให้ frontend
      const base64Image = Buffer.from(image).toString('base64');
      res.json({ status: 'OK', image: base64Image });
    } else {
      res.status(404).json({ status: 'error', message: 'ไม่พบภาพนี้' });
    }
  } catch (error) {
    console.error('Error:', error);
    res.status(500).json({ status: 'error', message: 'เกิดข้อผิดพลาดในการดึงภาพ' });
  }
});


// เพิ่มเส้นทาง API สำหรับลบภาพ
app.delete('/api/images/:id', async (req, res) => {
  try {
      const { id } = req.params;
      const [result] = await db.execute('DELETE FROM images WHERE id = ?', [id]);

      if (result.affectedRows > 0) {
          res.json({ status: 'OK', message: 'ลบภาพสำเร็จ' });
      } else {
          res.status(404).json({ status: 'error', message: 'ไม่พบภาพนี้' });
      }
  } catch (error) {
      console.error('Error:', error);
      res.status(500).json({ status: 'error', message: 'เกิดข้อผิดพลาดในการลบภาพ' });
  }
});

// เพิ่มเส้นทาง API สำหรับการอัปเดตรูปภาพ
app.put('/api/images/:id', upload, async (req, res) => {
    try {
        const { id } = req.params;
        const image = req.file?.buffer; // รับไฟล์ใหม่จากการอัปโหลด

        if (!image) {
            return res.status(400).json({ status: 'error', message: 'กรุณาอัปโหลดไฟล์ภาพใหม่' });
        }

        // อัปเดตไฟล์ภาพในฐานข้อมูล
        const [result] = await db.execute(
            'UPDATE images SET image = ? WHERE id = ?',
            [image, id]
        );

        if (result.affectedRows > 0) {
            res.json({ status: 'OK', message: 'อัปเดตรูปภาพสำเร็จ' });
        } else {
            res.status(404).json({ status: 'error', message: 'ไม่พบภาพนี้' });
        }
    } catch (error) {
        console.error('Error:', error);
        res.status(500).json({ status: 'error', message: 'เกิดข้อผิดพลาดในการอัปเดตรูปภาพ' });
    }
});


app.post('/api/register', async (req, res) => {
  const { username, password, confirmPassword } = req.body;

  // ตรวจสอบว่า password และ confirmPassword ตรงกันหรือไม่
  if (password !== confirmPassword) {
    return res.status(400).json({ status: 'error', message: 'Password และ Confirm Password ต้องตรงกัน' });
  }

  // ตรวจสอบว่า username มีอยู่แล้วในฐานข้อมูลหรือไม่
  const [existingUser] = await db.execute('SELECT * FROM users WHERE user = ?', [username]);
  if (existingUser.length > 0) {
    return res.status(400).json({ status: 'error', message: 'Username นี้ถูกใช้งานแล้ว' });
  }

  // แฮช password ก่อนเก็บในฐานข้อมูล
  const hashedPassword = await bcrypt.hash(password, saltRounds);

  // เพิ่ม user ลงในฐานข้อมูล
  try {
    await db.execute('INSERT INTO users (user, password) VALUES (?, ?)', [username, hashedPassword]);
    res.json({ status: 'OK', message: 'สมัครสมาชิกสำเร็จ' });
  } catch (error) {
    console.error('Error:', error);
    res.status(500).json({ status: 'error', message: 'เกิดข้อผิดพลาดในการสมัครสมาชิก' });
  }
});
app.post('/api/login', async (req, res) => {
  const { username, password } = req.body;

  // ตรวจสอบว่า username และ password ไม่เป็น undefined
  if (!username || !password) {
    return res.status(400).json({ status: 'error', message: 'Username หรือ Password ต้องไม่เป็นค่าว่าง' });
  }

  // ค้นหา user ในฐานข้อมูล
  const [rows] = await db.execute('SELECT * FROM users WHERE user = ?', [username]);

  if (rows.length > 0) {
    // ตรวจสอบรหัสผ่านที่ผู้ใช้กรอก
    const isPasswordValid = await bcrypt.compare(password, rows[0].password);
    
    if (isPasswordValid) {
      // เก็บข้อมูล user, role, และ nickname ใน session
      req.session.user = {
        id: rows[0].id,
        user: rows[0].user,
        role: rows[0].role,
        nickname: rows[0].nickname  // เก็บ nickname ด้วย
      };

      // ถ้าเป็น admin ให้ไปหน้า admin dashboard
      if (rows[0].role === 'admin') {
        res.json({ status: 'OK', role: 'admin', redirect: '/admin-dashboard' });
      } else {
        // ถ้าเป็น user ให้ไปหน้า main
        res.json({ status: 'OK', role: 'user', redirect: '/home' });
      }
    } else {
      res.status(401).json({ status: 'error', message: 'Invalid credentials' });
    }
  } else {
    res.status(401).json({ status: 'error', message: 'Invalid credentials' });
  }
});

app.get('/api/user', (req, res) => {
  if (req.session.user) {
    // ส่งข้อมูลผู้ใช้ที่ล็อกอินอยู่จาก session รวมถึง nickname
    res.json({
      status: 'OK',
      user: req.session.user  // ส่งข้อมูลทั้งหมดรวมถึง nickname
    });
  } else {
    res.status(401).json({ status: 'error', message: 'ยังไม่ได้ล็อกอิน' });
  }
});

app.get('/api/check-session', (req, res) => {
  if (req.session.user) {
    // ถ้า session มีข้อมูล user แสดงว่า login อยู่
    res.json({ loggedIn: true });
  } else {
    // ถ้า session ไม่มีข้อมูล user แสดงว่าไม่ได้ login
    res.json({ loggedIn: false });
  }
});

app.post('/api/logout', (req, res) => {
  // ทำลาย session เมื่อผู้ใช้ล็อกเอาท์
  req.session.destroy((err) => {
    if (err) {
      return res.status(500).json({ status: 'error', message: 'Failed to log out' });
    }
    
    // รีไดเร็กต์กลับไปที่หน้า login หรือหน้าอื่นๆ ที่ต้องการ
    res.json({ status: 'OK', message: 'Logged out successfully' });
  });
});

async function getImageFromDatabase(imageId) {
  const [rows] = await db.execute('SELECT image FROM images WHERE id = ?', [imageId]);
  return Buffer.from(rows[0].image);
}

// ฟังก์ชันสร้างภาพซ้อนกัน
async function addTextToImage(imageBuffer, text) {
  try {
      // โหลดภาพด้วย sharp
      const image = sharp(imageBuffer);
      const metadata = await image.metadata();
      const width = metadata.width;
      const height = metadata.height;

      // สร้าง canvas ที่มีขนาดเท่ากับภาพ
      const canvas = createCanvas(width, height);
      const ctx = canvas.getContext('2d');

      // โหลดภาพเข้า canvas
      const img = await loadImage(imageBuffer);
      ctx.drawImage(img, 0, 0);

      // ตั้งค่าฟอนต์และสีข้อความ
      ctx.font = '40px Arial';
      ctx.fillStyle = 'white';
      ctx.textAlign = 'center';
      ctx.textBaseline = 'middle';

      // เพิ่มข้อความลงในภาพ
      ctx.fillText(text, width / 2, height - 50); // ข้อความอยู่ที่กลางล่างของภาพ

      // แปลง canvas กลับเป็น buffer และบันทึกด้วย sharp
      const bufferWithText = canvas.toBuffer();
      const finalImage = await sharp(bufferWithText)
          .toBuffer();

      return finalImage;
  } catch (error) {
      console.error('Error processing images:', error);
      throw error;
  }
}


// API สำหรับสร้างภาพซ้อนกัน
async function createLayeredImage(jdImage, flowerImage, topFlagImage, lowFlagImage, candleImage, backgroundImage, text) {
  // กำหนดขนาดที่ต้องการ
  const width = 800;
  const height = 800;

  // ปรับขนาดภาพทั้งหมดให้มีขนาดเดียวกัน
  const resizedJdImage = await sharp(jdImage).resize(width, height).toBuffer();
  const resizedFlowerImage = await sharp(flowerImage).resize(width, height).toBuffer();
  const resizedTopFlagImage = await sharp(topFlagImage).resize(width, height).toBuffer();
  const resizedLowFlagImage = await sharp(lowFlagImage).resize(width, height).toBuffer();
  const resizedCandleImage = await sharp(candleImage).resize(width, height).toBuffer();
  const resizedBackgroundImage = await sharp(backgroundImage).resize(width, height).toBuffer();

  // ซ้อนภาพทั้งหมด
  const image = sharp(resizedBackgroundImage)
      .composite([
          { input: resizedJdImage, gravity: 'center' },
          { input: resizedFlowerImage, gravity: 'center' },
          { input: resizedTopFlagImage, gravity: 'center' },
          { input: resizedLowFlagImage, gravity: 'center' },
          { input: resizedCandleImage, gravity: 'center' }
      ])
      .resize(width, height) // กำหนดขนาดของภาพสุดท้าย
      .toBuffer();

  return image;
}

// API สำหรับสร้างภาพซ้อนกัน
app.post('/api/layered-image', async (req, res) => {
  try {
      const { jd, flower, topFlag, lowFlag, candle, background, text, decorations_type } = req.body;

      // ดึงข้อมูลภาพจากฐานข้อมูล
      const jdImage = await getImageFromDatabase(jd);
      const flowerImage = await getImageFromDatabase(flower);
      const topFlagImage = await getImageFromDatabase(topFlag);
      const lowFlagImage = await getImageFromDatabase(lowFlag);
      const candleImage = await getImageFromDatabase(candle);
      const backgroundImage = await getImageFromDatabase(background);

      // สร้างภาพซ้อนกัน
      const layeredImage = await createLayeredImage(
          jdImage,
          flowerImage,
          topFlagImage,
          lowFlagImage,
          candleImage,
          backgroundImage,
          text
      );

      // ส่งภาพซ้อนกันในรูปแบบ base64
      res.json({ status: 'OK', image: layeredImage.toString('base64') });
  } catch (error) {
      console.error('Error creating layered image:', error);
      res.status(500).json({ status: 'error', message: 'ไม่สามารถสร้างภาพได้' });
  }
});



app.get('/api/categories', async (req, res) => {
  try {
      const query = 'SELECT DISTINCT category FROM images WHERE category IN (?, ?, ?, ?, ?, ?)';
      const categories = ['JD', 'Flower', 'TopFlag', 'LowFlag', 'Candle', 'Background'];

      connection.query(query, categories, (err, results) => {
          if (err) {
              return res.status(500).json({ status: 'error', message: err.message });
          }

          const decorationsTypes = ['JD1', 'JD2'];  // Decorations type ที่ต้องการให้เลือก
          res.json({ categories: results, decorationsTypes });
      });
  } catch (err) {
      res.status(500).json({ status: 'error', message: err.message });
  }
});

// ฟังก์ชันดึงข้อมูลภาพจากฐานข้อมูล
app.get('/api/images/check/:decorations_type', (req, res) => {
  const { decorations_type } = req.params;

  if (!decorations_type) {
      return res.status(400).json({ message: "Decorations type is required." });
  }

  // ตรวจสอบให้แน่ใจว่า query ดึงข้อมูลได้ถูกต้อง
  const query = `
      SELECT id, category, name, image
      FROM images
      WHERE decorations_type = ?
      AND category IN ('JD', 'Flower', 'TopFlag', 'LowFlag', 'Candle', 'Background');
  `;

  connection.query(query, [decorations_type], (err, results) => {
      if (err) {
          console.error('Error fetching images:', err);
          return res.status(500).json({ message: "Database error occurred." });
      }

      if (results.length === 0) {
          return res.status(404).json({ message: `No images found for decorations_type: ${decorations_type}` });
      }

      res.json({ images: results });
  });
});

app.get('/api/users/nickname', async (req, res) => {
  try {
    // ตรวจสอบว่าผู้ใช้ได้ล็อกอินหรือไม่
    if (!req.session || !req.session.userId) {
      return res.status(401).json({ status: 'error', message: 'กรุณาล็อกอินก่อน' });
    }

    const userId = req.session.userId;  // ดึง userId จาก session (หรือ token ถ้าใช้ JWT)
    
    // ดึงข้อมูล nickname จากฐานข้อมูลโดยใช้ userId
    const [rows] = await db.execute('SELECT nickname FROM users WHERE id = ?', [userId]);
    
    if (rows.length > 0) {
      const nickname = rows[0].nickname;
      res.json({ status: 'OK', nickname: nickname });
    } else {
      res.status(404).json({ status: 'error', message: 'ไม่พบชื่อผู้ใช้' });
    }
  } catch (error) {
    console.error('Error:', error);
    res.status(500).json({ status: 'error', message: 'เกิดข้อผิดพลาดในการดึงข้อมูล' });
  }
});

app.get('/', (req, res) => {
  res.sendFile(path.join(htmlPath, 'main_user.html'));
});

app.get('/card', (req, res) => {
  res.sendFile(path.join(htmlPath, 'card.html'));
});

app.get('/login', (req, res) => {
  res.sendFile(path.join(htmlPath, 'login.html'));
});

app.get('/admin-dashboard', (req, res) =>{
  res.sendFile(path.join(htmlPath, 'main_admin.html'))
})

app.get('/activity', (req, res) => {
  res.sendFile(path.join(htmlPath, 'activity.html'));
})

app.get('/home', (req, res) => {
  res.sendFile(path.join(htmlPath, 'main_user.html'));
});

app.get('/register', (req, res) => {
  res.sendFile(path.join(htmlPath, 'register.html'));
});

// เริ่มต้นเซิร์ฟเวอร์
app.listen(PORT, () => {
  console.log(`Backend server running on port ${PORT}`);
});

