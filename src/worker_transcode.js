import { S3Client, GetObjectCommand, PutObjectCommand } from "@aws-sdk/client-s3";
import { createWriteStream, createReadStream, promises as fs } from "fs";
import path from "path";
import { pipeline } from "stream/promises";
import { spawn } from "child_process";
import crypto from "crypto";

const s3 = new S3Client({
  region: process.env.S3_REGION,
  endpoint: process.env.S3_ENDPOINT,
  forcePathStyle: true,
  credentials: {
    accessKeyId: process.env.S3_ACCESS_KEY,
    secretAccessKey: process.env.S3_SECRET_KEY,
  },
});

async function downloadFromS3(key, toPath){
  const cmd = new GetObjectCommand({ Bucket: process.env.S3_BUCKET, Key: key });
  const res = await s3.send(cmd);
  await pipeline(res.Body, createWriteStream(toPath));
}

async function uploadFolderToS3(localDir, s3Prefix){
  const entries = await fs.readdir(localDir, { withFileTypes: true });
  for(const ent of entries){
    const p = path.join(localDir, ent.name);
    const key = s3Prefix + ent.name + (ent.isDirectory() ? "/" : "");
    if(ent.isDirectory()){
      await uploadFolderToS3(p, key);
    } else {
      const Body = createReadStream(p);
      const ContentType = ent.name.endsWith(".m3u8") ? "application/x-mpegURL"
                         : ent.name.endsWith(".ts") ? "video/MP2T"
                         : "application/octet-stream";
      await s3.send(new PutObjectCommand({
        Bucket: process.env.S3_BUCKET, Key: key, Body, ContentType, ACL: "public-read"
      }));
    }
  }
}

async function transcodeToHLS(inputPath, outDir){
  await fs.mkdir(outDir, { recursive: true });
  const args = [
    "-i", inputPath,
    "-filter:v:0", "scale=w=-2:h=426", "-c:v:0", "libx264", "-b:v:0", "400k",  "-c:a:0", "aac", "-b:a:0", "96k",
    "-filter:v:1", "scale=w=-2:h=854", "-c:v:1", "libx264", "-b:v:1", "1200k", "-c:a:1", "aac", "-b:a:1", "128k",
    "-filter:v:2", "scale=w=-2:h=1280","-c:v:2","libx264","-b:v:2","2500k","-c:a:2","aac","-b:a:2","128k",
    "-var_stream_map","v:0,a:0 v:1,a:1 v:2,a:2",
    "-preset","veryfast","-hls_time","6","-hls_playlist_type","vod",
    "-hls_segment_filename", path.join(outDir, "out_%v","seg_%03d.ts"),
    "-master_pl_name","master.m3u8","-f","hls","-use_localtime_mkdir","1",
    path.join(outDir, "out_%v","index.m3u8")
  ];
  await new Promise((resolve, reject)=>{
    const p = spawn("ffmpeg", args, { stdio: "inherit" });
    p.on("exit", code => code === 0 ? resolve() : reject(new Error("ffmpeg failed "+code)));
  });
}

async function main(){
  const s3Key = process.argv[2];
  if(!s3Key){ 
    console.log("Usage: node src/worker_transcode.js <s3Key>");
    process.exit(1);
  }
  const tmp = "/tmp/" + crypto.randomUUID();
  await fs.mkdir(tmp, { recursive: true });
  const input = path.join(tmp, "input.mp4");
  console.log("Downloading from S3:", s3Key);
  await downloadFromS3(s3Key, input);
  const outDir = path.join(tmp, "hls");
  console.log("Transcoding to HLS...");
  await transcodeToHLS(input, outDir);
  const videoId = path.basename(s3Key).replace(/\.[^.]+$/, "");
  const prefix = `videos/hls/${videoId}/`;
  console.log("Uploading HLS to S3 prefix:", prefix);
  await uploadFolderToS3(outDir, prefix);
  console.log("Done. Master playlist:", `${process.env.CDN_BASE_URL}/${prefix}master.m3u8`);
}
main().catch(e=>{ console.error(e); process.exit(1); });
