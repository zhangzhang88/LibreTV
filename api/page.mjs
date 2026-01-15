import path from 'path';
import fs from 'fs/promises';
import crypto from 'crypto';

function sha256Hex(input) {
  return crypto.createHash('sha256').update(input).digest('hex');
}

export default async function handler(req, res) {
  try {
    const filePath = path.join(process.cwd(), 'index.html');
    let content = await fs.readFile(filePath, 'utf8');
    const password = process.env.PASSWORD || '';
    const passwordHash = password ? sha256Hex(password) : '';
    content = content.replace('{{PASSWORD}}', passwordHash);
    res.setHeader('Content-Type', 'text/html; charset=utf-8');
    res.status(200).send(content);
  } catch (error) {
    res.status(500).send('读取静态页面失败');
  }
}
