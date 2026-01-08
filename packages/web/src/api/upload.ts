import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import { execSync } from 'child_process';

/**
 * Save uploaded file and extract if ZIP
 */
export async function handleUpload(
  fileBuffer: Buffer,
  filename: string
): Promise<{ path: string; cleanup: () => void }> {
  // Create temp directory
  const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'arcshield-upload-'));

  try {
    const isZip = filename.endsWith('.zip') || fileBuffer[0] === 0x50 && fileBuffer[1] === 0x4b;

    if (isZip) {
      // Save and extract ZIP
      const zipPath = path.join(tempDir, 'upload.zip');
      fs.writeFileSync(zipPath, fileBuffer);

      const extractDir = path.join(tempDir, 'extracted');
      fs.mkdirSync(extractDir);

      console.log(`[Upload] Extracting ZIP to ${extractDir}...`);
      execSync(`unzip -q ${zipPath} -d ${extractDir}`, { stdio: 'pipe' });

      // Check if ZIP contains a single root folder
      const contents = fs.readdirSync(extractDir);
      let scanPath = extractDir;

      if (contents.length === 1) {
        const singleItem = path.join(extractDir, contents[0]);
        if (fs.statSync(singleItem).isDirectory()) {
          scanPath = singleItem;
        }
      }

      console.log(`[Upload] Ready to scan: ${scanPath}`);

      return {
        path: scanPath,
        cleanup: () => {
          try {
            fs.rmSync(tempDir, { recursive: true, force: true });
            console.log(`[Upload] Cleaned up ${tempDir}`);
          } catch (e) {
            console.error(`[Upload] Failed to cleanup:`, e);
          }
        },
      };
    } else {
      // Single file - just save it
      const filePath = path.join(tempDir, filename);
      fs.writeFileSync(filePath, fileBuffer);

      return {
        path: tempDir,
        cleanup: () => {
          try {
            fs.rmSync(tempDir, { recursive: true, force: true });
          } catch (e) {
            console.error(`[Upload] Failed to cleanup:`, e);
          }
        },
      };
    }
  } catch (error) {
    // Cleanup on error
    fs.rmSync(tempDir, { recursive: true, force: true });
    throw new Error(`Failed to process upload: ${error instanceof Error ? error.message : 'Unknown error'}`);
  }
}
