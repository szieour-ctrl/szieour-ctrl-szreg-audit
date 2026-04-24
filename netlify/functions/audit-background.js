/**
 * SZREG AI Compliance Audit — Netlify Background Function
 * File: netlify/functions/audit-background.js
 *
 * Background functions run up to 15 minutes — no timeout concern.
 * Triggered by form submission, fires Pabbly webhook when complete.
 *
 * Flow:
 *  1. Parse intake payload
 *  2. Authenticate to Google Drive
 *  3. Navigate to transaction folder → Active Transaction → Executed Docs
 *  4. Download every PDF in E1–E5 as base64
 *  5. Send all documents + compliance prompt to Claude
 *  6. POST structured report to Pabbly webhook
 */

const https = require('https');

// ─── Pabbly webhook URL ───────────────────────────────────────────────────────
// Replace with your actual Pabbly webhook URL for the compliance report workflow
const PABBLY_WEBHOOK_URL = 'https://connect.pabbly.com/workflow/sendwebhookdata/IjU3NjcwNTZlMDYzNDA0MzU1MjY4NTUzNTUxMzQi_pc';

// ─── Google Drive folder ID ───────────────────────────────────────────────────
const RE_TRANSACTIONS_FOLDER = '1iuTI1fKo4IZps9hzXLPFoI3TUT3NaCKI';

// ─── Google Auth ──────────────────────────────────────────────────────────────

function base64url(str) {
  return Buffer.from(str).toString('base64')
    .replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
}

async function getGoogleAccessToken() {
  const rawKey = process.env.GOOGLE_SERVICE_ACCOUNT_KEY;
  if (!rawKey) throw new Error('GOOGLE_SERVICE_ACCOUNT_KEY not set');

  let key;
  try {
    key = JSON.parse(rawKey);
  } catch (e) {
    try {
      key = JSON.parse(rawKey.trim().replace(/^"|"$/g, ''));
    } catch (e2) {
      throw new Error('Failed to parse GOOGLE_SERVICE_ACCOUNT_KEY');
    }
  }

  const privateKey = key.private_key.replace(/\\n/g, '\n');
  const now = Math.floor(Date.now() / 1000);
  const header = base64url(JSON.stringify({ alg: 'RS256', typ: 'JWT' }));
  const claim = base64url(JSON.stringify({
    iss: key.client_email,
    // Need both readonly and drive scope to download file content
    scope: 'https://www.googleapis.com/auth/drive.readonly',
    aud: 'https://oauth2.googleapis.com/token',
    exp: now + 3600,
    iat: now
  }));

  const { createSign } = require('crypto');
  const sign = createSign('RSA-SHA256');
  sign.update(`${header}.${claim}`);
  const sig = sign.sign(privateKey, 'base64')
    .replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
  const jwt = `${header}.${claim}.${sig}`;

  return new Promise((resolve, reject) => {
    const body = `grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Ajwt-bearer&assertion=${jwt}`;
    const req = https.request({
      hostname: 'oauth2.googleapis.com',
      path: '/token',
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' }
    }, res => {
      let data = '';
      res.on('data', c => data += c);
      res.on('end', () => {
        const parsed = JSON.parse(data);
        if (parsed.access_token) resolve(parsed.access_token);
        else reject(new Error('Token error: ' + data));
      });
    });
    req.on('error', reject);
    req.write(body);
    req.end();
  });
}

// ─── Drive API helpers ────────────────────────────────────────────────────────

function driveRequest(path, token) {
  return new Promise((resolve, reject) => {
    const req = https.request({
      hostname: 'www.googleapis.com',
      path,
      method: 'GET',
      headers: { Authorization: `Bearer ${token}` }
    }, res => {
      let data = '';
      res.on('data', c => data += c);
      res.on('end', () => {
        try { resolve(JSON.parse(data)); }
        catch (e) { resolve({ error: 'JSON parse failed', raw: data.substring(0, 200) }); }
      });
    });
    req.on('error', reject);
    req.end();
  });
}

async function listFolderContents(folderId, token) {
  const q = encodeURIComponent(`'${folderId}' in parents and trashed = false`);
  const fields = encodeURIComponent('files(id,name,mimeType,size)');
  const result = await driveRequest(
    `/drive/v3/files?q=${q}&fields=${fields}&pageSize=100`,
    token
  );
  return result.files || [];
}

// Download a file from Drive as base64
async function downloadFileAsBase64(fileId, token) {
  return new Promise((resolve, reject) => {
    const req = https.request({
      hostname: 'www.googleapis.com',
      path: `/drive/v3/files/${fileId}?alt=media`,
      method: 'GET',
      headers: { Authorization: `Bearer ${token}` }
    }, res => {
      const chunks = [];
      res.on('data', c => chunks.push(c));
      res.on('end', () => {
        const buffer = Buffer.concat(chunks);
        resolve(buffer.toString('base64'));
      });
    });
    req.on('error', reject);
    req.end();
  });
}

// ─── HTTP POST helper (for Pabbly webhook) ───────────────────────────────────

function postJSON(urlString, payload) {
  return new Promise((resolve, reject) => {
    const body = JSON.stringify(payload);
    const url = new URL(urlString);
    const req = https.request({
      hostname: url.hostname,
      path: url.pathname + url.search,
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Content-Length': Buffer.byteLength(body)
      }
    }, res => {
      let data = '';
      res.on('data', c => data += c);
      res.on('end', () => resolve(data));
    });
    req.on('error', reject);
    req.write(body);
    req.end();
  });
}

// ─── Main handler ─────────────────────────────────────────────────────────────

exports.handler = async (event) => {
  // Background functions must return 202 immediately — processing happens async
  // But we still do the work inside the handler (Netlify handles the background execution)

  const body = JSON.parse(event.body || '{}');
  const {
    lastNameSearch,
    transactionType,
    yearBuilt,
    hoaPresent,
    poolPresent,
    dualAgency,
    community55plus,
    submittedBy,
    agentEmail,
    auditDate
  } = body;

  console.log(`[AUDIT] Starting compliance audit for: ${lastNameSearch}`);

  try {
    // ── 1. Authenticate ───────────────────────────────────────────────────────
    const token = await getGoogleAccessToken();
    console.log('[AUDIT] Google auth successful');

    // ── 2. Find transaction folder ────────────────────────────────────────────
    const typeKeyword = transactionType === 'BUYER' ? 'Buyer' : 'Listing';
    const q = encodeURIComponent(
      `'${RE_TRANSACTIONS_FOLDER}' in parents and name contains '${lastNameSearch}' and mimeType = 'application/vnd.google-apps.folder' and trashed = false`
    );
    const searchResult = await driveRequest(
      `/drive/v3/files?q=${q}&fields=files(id,name)&pageSize=10`,
      token
    );

    const folders = searchResult.files || [];
    if (folders.length === 0) {
      await postJSON(PABBLY_WEBHOOK_URL, {
        status: 'error',
        error: `No transaction folder found for "${lastNameSearch}"`,
        submittedBy,
        agentEmail,
        auditDate
      });
      return { statusCode: 202 };
    }

    const txFolder = folders.find(f => f.name.includes(typeKeyword)) || folders[0];
    console.log(`[AUDIT] Found folder: ${txFolder.name}`);

    // ── 3. Navigate to Executed Docs ──────────────────────────────────────────
    const parentContents = await listFolderContents(txFolder.id, token);

    const activeTransaction = parentContents.find(f =>
      f.name.includes('Active Transaction') && f.mimeType === 'application/vnd.google-apps.folder'
    );
    if (!activeTransaction) {
      await postJSON(PABBLY_WEBHOOK_URL, {
        status: 'error',
        error: `Active Transaction folder not found in ${txFolder.name}`,
        folderName: txFolder.name,
        submittedBy,
        agentEmail,
        auditDate
      });
      return { statusCode: 202 };
    }

    const atContents = await listFolderContents(activeTransaction.id, token);
    const execDocs = atContents.find(f =>
      f.name.includes('Executed Docs') && f.mimeType === 'application/vnd.google-apps.folder'
    );
    if (!execDocs) {
      await postJSON(PABBLY_WEBHOOK_URL, {
        status: 'error',
        error: `Executed Docs folder not found — has Offer Accepted been run?`,
        folderName: txFolder.name,
        submittedBy,
        agentEmail,
        auditDate
      });
      return { statusCode: 202 };
    }

    // ── 4. Download all PDFs from E1–E5 ──────────────────────────────────────
    const eSubfolders = await listFolderContents(execDocs.id, token);
    const documentsBySection = {};
    const claudeDocuments = []; // Array of {source, type, folder, filename} for Claude API

    for (const subfolder of eSubfolders) {
      if (subfolder.mimeType !== 'application/vnd.google-apps.folder') continue;

      const sectionLabel = subfolder.name;
      const files = await listFolderContents(subfolder.id, token);
      documentsBySection[sectionLabel] = [];

      console.log(`[AUDIT] Processing ${sectionLabel}: ${files.length} files`);

      for (const file of files) {
        if (file.mimeType === 'application/vnd.google-apps.folder') continue;

        // Only download PDFs and common document types
        const isPDF = file.mimeType === 'application/pdf' ||
                      file.name.toLowerCase().endsWith('.pdf');
        const isDoc = file.mimeType === 'application/vnd.google-apps.document';

        const fileSizeKB = parseInt(file.size || 0) / 1024;

        documentsBySection[sectionLabel].push({
          name: file.name,
          sizeKB: Math.round(fileSizeKB),
          type: isPDF ? 'pdf' : file.mimeType
        });

        if (isPDF && fileSizeKB < 15000) {
          // Download files under 15MB — skip enormous scanned packages
          try {
            const base64Data = await downloadFileAsBase64(file.id, token);
            claudeDocuments.push({
              folder: sectionLabel,
              filename: file.name,
              sizeKB: Math.round(fileSizeKB),
              base64: base64Data
            });
            console.log(`[AUDIT] Downloaded: ${file.name} (${Math.round(fileSizeKB)}KB)`);
          } catch (dlErr) {
            console.error(`[AUDIT] Failed to download ${file.name}:`, dlErr.message);
            // Still note the file exists, just couldn't read it
            claudeDocuments.push({
              folder: sectionLabel,
              filename: file.name,
              sizeKB: Math.round(fileSizeKB),
              base64: null,
              downloadError: dlErr.message
            });
          }
        } else if (fileSizeKB >= 15000) {
          // File too large to download — note it exists but flag for agent
          claudeDocuments.push({
            folder: sectionLabel,
            filename: file.name,
            sizeKB: Math.round(fileSizeKB),
            base64: null,
            downloadError: 'File exceeds 15MB — not downloaded, presence noted only'
          });
        }
      }
    }

    console.log(`[AUDIT] Total documents found: ${claudeDocuments.length}`);

    // ── 5. Build Claude compliance prompt ────────────────────────────────────
    const conditions = {
      transactionType,
      yearBuilt,
      isPreX1978: yearBuilt && parseInt(yearBuilt) < 1978,
      hoaPresent: hoaPresent === 'yes',
      poolPresent: poolPresent === 'yes',
      dualAgency: dualAgency === 'yes',
      community55plus: community55plus === 'yes'
    };

    const auditReport = await callClaudeWithDocuments(
      txFolder.name,
      conditions,
      claudeDocuments,
      submittedBy
    );

    console.log('[AUDIT] Claude compliance analysis complete');

    // ── 6. Build inventory summary for Pabbly ────────────────────────────────
    const inventorySummary = Object.entries(documentsBySection).map(([folder, files]) => {
      return `${folder} (${files.length} files):\n${files.map(f => `  • ${f.name} (${f.sizeKB}KB)`).join('\n')}`;
    }).join('\n\n');

    // ── 7. Fire Pabbly webhook with completed report ──────────────────────────
    await postJSON(PABBLY_WEBHOOK_URL, {
      status: 'complete',
      folderName: txFolder.name,
      folderId: txFolder.id,
      submittedBy,
      agentEmail,
      auditDate,
      transactionType,
      conditions,
      inventorySummary,
      report: auditReport,
      // Pre-formatted for Google Doc / email
      reportFormatted: formatReportAsText(txFolder.name, auditReport, submittedBy, auditDate, conditions)
    });

    console.log('[AUDIT] Pabbly webhook fired — audit complete');
    return { statusCode: 202 };

  } catch (err) {
    console.error('[AUDIT] Fatal error:', err.message, err.stack);

    // Notify via Pabbly even on error
    try {
      await postJSON(PABBLY_WEBHOOK_URL, {
        status: 'error',
        error: err.message,
        submittedBy,
        agentEmail,
        auditDate,
        folderName: lastNameSearch
      });
    } catch (webhookErr) {
      console.error('[AUDIT] Could not fire error webhook:', webhookErr.message);
    }

    return { statusCode: 202 };
  }
};

// ─── Claude API call with actual document content ─────────────────────────────

async function callClaudeWithDocuments(folderName, conditions, documents, submittedBy) {
  const { transactionType, yearBuilt, isPreX1978, hoaPresent, poolPresent, dualAgency, community55plus } = conditions;
  const isBuyer = transactionType === 'BUYER';

  // Build the message content array — text prompt first, then documents
  const messageContent = [];

  // System instructions as first text block
  messageContent.push({
    type: 'text',
    text: buildCompliancePrompt(folderName, conditions, submittedBy, documents)
  });

  // Attach each PDF document that was successfully downloaded
  let documentsAttached = 0;
  for (const doc of documents) {
    if (doc.base64) {
      messageContent.push({
        type: 'document',
        source: {
          type: 'base64',
          media_type: 'application/pdf',
          data: doc.base64
        },
        title: `[${doc.folder}] ${doc.filename}`,
        // Cache control for large repeated documents
        cache_control: { type: 'ephemeral' }
      });
      documentsAttached++;
    }
  }

  console.log(`[CLAUDE] Sending ${documentsAttached} documents for analysis`);

  return new Promise((resolve, reject) => {
    const body = JSON.stringify({
      model: 'claude-sonnet-4-20250514',
      max_tokens: 8000,
      system: `You are the SZREG AI Compliance Auditor for SZ Real Estate Group. You perform rigorous transaction compliance reviews by reading actual documents — not guessing from filenames. You identify True Risks (missing documents, blank signatures, unexecuted forms), Manageable Items (minor issues needing verification), and confirm Clear items with specific evidence from the documents you read. You are thorough, precise, and never infer — you only report what you can actually verify from document content.`,
      messages: [
        {
          role: 'user',
          content: messageContent
        }
      ]
    });

    const req = https.request({
      hostname: 'api.anthropic.com',
      path: '/v1/messages',
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'x-api-key': process.env.ANTHROPIC_API_KEY,
        'anthropic-version': '2023-06-01',
        'anthropic-beta': 'pdfs-2024-09-25'  // Required for PDF document support
      }
    }, res => {
      let data = '';
      res.on('data', c => data += c);
      res.on('end', () => {
        try {
          const parsed = JSON.parse(data);
          const text = parsed.content?.[0]?.text || '';
          console.log('[CLAUDE] Response length:', text.length);
          const clean = text
            .replace(/^```json\s*/i, '')
            .replace(/^```\s*/i, '')
            .replace(/```\s*$/i, '')
            .trim();
          const result = JSON.parse(clean);
          result.trueRisk   = result.trueRisk   || [];
          result.manageable = result.manageable || [];
          result.clear      = result.clear      || [];
          result.summary    = result.summary    || 'Audit complete.';
          result.overallRisk = result.overallRisk || 'LOW';
          resolve(result);
        } catch (e) {
          console.error('[CLAUDE] Parse error:', e.message);
          // Return a structured error rather than crashing
          const rawText = (() => {
            try { return JSON.parse(data).content?.[0]?.text || data; }
            catch (x) { return data; }
          })();
          resolve({
            summary: 'Compliance analysis completed but response format error occurred. See manageable items.',
            overallRisk: 'MEDIUM',
            trueRisk: [],
            manageable: [{
              item: 'Report Parse Error',
              detail: 'Raw Claude response: ' + rawText.substring(0, 500),
              folder: 'System',
              evidence: ''
            }],
            clear: [],
            disclaimer: 'Audit incomplete — please re-run or contact support.'
          });
        }
      });
    });
    req.on('error', reject);
    req.write(body);
    req.end();
  });
}

// ─── Compliance prompt builder ────────────────────────────────────────────────

function buildCompliancePrompt(folderName, conditions, submittedBy, documents) {
  const { transactionType, yearBuilt, isPreX1978, hoaPresent, poolPresent, dualAgency, community55plus } = conditions;
  const isBuyer = transactionType === 'BUYER';

  // List documents that couldn't be read (download failures or oversized)
  const unreadable = documents.filter(d => !d.base64);
  const unreadableNote = unreadable.length > 0
    ? `\nNOTE — The following files could not be read (presence confirmed by filename only):\n${unreadable.map(d => `  • [${d.folder}] ${d.filename} — ${d.downloadError}`).join('\n')}\n`
    : '';

  // Map of all documents by folder for reference
  const docInventory = {};
  for (const doc of documents) {
    if (!docInventory[doc.folder]) docInventory[doc.folder] = [];
    docInventory[doc.folder].push(`${doc.filename} (${doc.sizeKB}KB)${doc.base64 ? ' [READABLE]' : ' [FILENAME ONLY]'}`);
  }
  const inventoryText = Object.entries(docInventory).map(([folder, files]) =>
    `${folder}:\n${files.map(f => `  • ${f}`).join('\n')}`
  ).join('\n\n');

  return `SZREG AI COMPLIANCE AUDIT
Transaction: ${folderName}
Submitted by: ${submittedBy}
Type: ${isBuyer ? 'Buyer Representation' : 'Seller Representation'}
Year Built: ${yearBuilt || 'Not provided'}
Conditions: Pre-1978=${isPreX1978 ? 'YES' : 'No'} | HOA=${hoaPresent ? 'YES' : 'No'} | Pool=${poolPresent ? 'YES' : 'No'} | Dual Agency=${dualAgency ? 'YES' : 'No'} | 55+=${community55plus ? 'YES' : 'No'}
${unreadableNote}
DOCUMENT INVENTORY (all files found in E1–E5):
${inventoryText}

ALL READABLE DOCUMENTS ARE ATTACHED. You have the actual PDF content for each [READABLE] file above.

═══════════════════════════════════════════════════════
YOUR COMPLIANCE TASK — READ THE ACTUAL DOCUMENTS
═══════════════════════════════════════════════════════

For each required document below, you MUST:
1. Open and read the actual attached PDF
2. Confirm specific evidence: party names, dates, signature presence, Authentisign/DocuSign IDs
3. Cross-reference where required (commission % vs RPA, party names consistent across docs)
4. Never infer or guess — only report what you can actually read

REQUIRED DOCUMENTS & WHAT TO VERIFY:

━━━ E1 — CONTRACTS & ADDENDUMS ━━━━━━━━━━━━━━━━━━━━━━━━━━━
• Residential Purchase Agreement (RPA)
  - Verify: Buyer and Seller names on page 1, property address, purchase price, closing date
  - Note: commission percentage agreed — cross-reference with Commission Demand Letter
  - Verify: executed (Authentisign ID or DocuSign envelope ID present, or wet signatures with dates)

• ${isBuyer ? 'Buyer Representation & Broker Compensation (BRBC)' : 'Listing Agreement (LA)'}
  - Verify: client name matches RPA, agent/broker name, commission terms, execution status

• Agency Disclosure (AD)
  - Verify: present and executed by all parties

• Contingency Removal (CR-B or CR)
  - Verify: present if applicable, contingencies listed, executed

• Request for Repair (RR/RFR) — if present
  - Verify: repair items listed, dollar amounts, executed by requesting party
  - CRITICAL: Note whether pest clearance or pest work was included in any RFR
  - Note total repair credit or work agreed to

• Seller Response to RFR (RRRR) — if RFR was submitted
  - Verify: response matches RFR items, executed

• Extension of Time (ETA) — if present
  - Verify: new dates, executed by all parties

━━━ E2 — DISCLOSURES ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
• Transfer Disclosure Statement (TDS)
  - Verify: seller names match RPA, property address, all sections completed
  - Verify: agent inspection section completed by listing agent
  - Verify: executed by all sellers and buyers

• Seller Property Questionnaire (SPQ)
  - Verify: present (may be a standalone file or bundled in a disclosure compilation)
  - Verify: seller names, executed

• Agent Visual Inspection Disclosure (AVID)
  - Verify: agent name, property address, completed inspection items, executed

• Natural Hazard Disclosure (NHD)
  - Verify: present (may be in a combined disclosure package)
  - Verify: property address matches, executed

• Statewide Buyer & Seller Advisory (SBSA)
  - Verify: present (may be in a combined disclosure package)
  - Verify: executed

• Buyer's Inspection Advisory (BIA)
  - Verify: present (may be in a combined disclosure package)
  - Verify: executed

${isPreX1978 ? `• ⚠️ REQUIRED — Lead-Based Paint Disclosure (LPD) — PRE-1978 PROPERTY
  - Verify: present and executed by all parties
  - Verify: property address, seller acknowledgment, buyer acknowledgment` : ''}

${hoaPresent ? `• ⚠️ REQUIRED — HOA Documents Package
  - Verify: CC&Rs, Bylaws, Budget, Meeting Minutes present
  - Note any missing HOA documents` : ''}

${dualAgency ? `• ⚠️ REQUIRED — Possible Representation of Both (PRBS)
  - Verify: present, executed by all parties` : ''}

━━━ E3 — INSPECTIONS & RFR ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
• Pest Inspection Report
  - Verify: property address, inspector name/license, date
  - CRITICAL: Note whether Section 1 items were found or if report is clear
  - If Section 1 items found: clearance certificate IS required (especially if negotiated in RFR)
  - If report is clear (no Section 1): clearance certificate is NOT required

• Pest Section 1 Clearance Certificate — ONLY required if Section 1 items were found AND clearance was negotiated
  - If pest report shows Section 1 items AND an RFR addressed pest work: verify clearance cert is present
  - If pest report is clear: mark this as N/A — Not Required

• Home Inspection Report
  - Verify: property address, inspector, date, report present and complete

${poolPresent ? `• ⚠️ REQUIRED — Pool/Spa Inspection Report
  - Verify: present, covers pool and/or spa` : ''}

━━━ E4 — TITLE & ESCROW ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
• Preliminary Title Report
  - Verify: property address, vesting, any liens or encumbrances noted

• Earnest Money Deposit (EMD) confirmation
  - Verify: amount matches RPA, deposit confirmed by escrow

• Commission Demand Letter
  - IMPORTANT: SZ Real Estate Group uses their own branded "Official Commission Demand Letter"
  - The document may be filed as "CD-[address]", "Commission Demand", or similar
  - Verify: commission percentage matches RPA, broker name (John P. Klein / SZ Real Estate Group)
  - Verify: executed with Authentisign ID or broker signature
  - Verify: disbursement instructions present

• Home Warranty Order
  - Verify: present, property address, plan type if visible

━━━ E5 — HOA DOCS (if HOA present) ━━━━━━━━━━━━━━━━━━━━━━━
${hoaPresent ? `• CC&Rs, Bylaws, HOA Budget, Meeting Minutes
  - Verify each is present
  ${community55plus ? '• Age Verification document required for 55+ community — verify present' : ''}` : 'N/A — No HOA indicated'}

═══════════════════════════════════════════════════════
CROSS-REFERENCE CHECKS (read multiple documents together)
═══════════════════════════════════════════════════════
1. Commission %: Does the Commission Demand Letter percentage match what is in the RPA?
2. Party names: Are buyer and seller names spelled consistently across RPA, TDS, AVID, and Commission Demand?
3. Property address: Is the address consistent across all documents?
4. Pest clearance logic: Did the pest report find Section 1 items? Was pest work in any RFR? Is clearance cert present if required?
5. Repair amounts: Do any RFR repair credits/amounts appear consistent across the RFR, RRRR, and RPA addendums?

═══════════════════════════════════════════════════════
RATING DEFINITIONS
═══════════════════════════════════════════════════════
🔴 TRUE RISK — Required document is missing entirely, OR document is present but unexecuted (blank signature lines with no names), OR a cross-reference check reveals a material discrepancy (e.g. commission % mismatch). Requires action before COE.

🟡 MANAGEABLE — Document is present but has a minor issue: a page may be missing initials, a date field appears blank, or agent should verify a specific detail. Also flag if a document could only be confirmed by filename (not content) due to download failure.

✅ CLEAR — Document confirmed present and appears properly executed. Cite your specific evidence: party names found, Authentisign ID if present, page reference if helpful.

═══════════════════════════════════════════════════════
OUTPUT FORMAT
═══════════════════════════════════════════════════════
Return ONLY this JSON structure. No preamble, no markdown, no backticks.

{
  "summary": "3-4 sentence overall compliance assessment. Be specific — mention what was verified, what was found, and any material issues.",
  "overallRisk": "HIGH | MEDIUM | LOW",
  "trueRisk": [
    {
      "item": "document or issue name",
      "detail": "specific finding with evidence from the document",
      "evidence": "quote or cite the specific text, ID, or data point that supports this finding",
      "folder": "E1/E2/E3/E4/E5"
    }
  ],
  "manageable": [
    {
      "item": "document or issue name",
      "detail": "specific finding and recommended action",
      "evidence": "what you found or did not find",
      "folder": "E1/E2/E3/E4/E5"
    }
  ],
  "clear": [
    {
      "item": "document name",
      "detail": "confirmed present and executed",
      "evidence": "specific confirmation: party names, Authentisign ID, key data verified",
      "folder": "E1/E2/E3/E4/E5"
    }
  ],
  "crossReferenceFindings": [
    {
      "check": "description of cross-reference performed",
      "result": "PASS | FAIL | UNABLE TO VERIFY",
      "detail": "specific finding"
    }
  ],
  "disclaimer": "This report reflects AI analysis of actual document content from Google Drive. It confirms document presence and visible execution indicators but does not constitute legal review. Agent verification of each document is required before COE. SZ Real Estate Group."
}`;
}

// ─── Format report as readable text for email / Google Doc ───────────────────

function formatReportAsText(folderName, report, submittedBy, auditDate, conditions) {
  const riskEmoji = { HIGH: '🔴', MEDIUM: '🟡', LOW: '✅' };
  const riskLabel = { HIGH: 'HIGH RISK — Action Required Before COE', MEDIUM: 'MEDIUM RISK — Review Items Below', LOW: 'LOW RISK — File Appears Complete' };

  const lines = [];

  lines.push('═══════════════════════════════════════════════════════');
  lines.push('SZREG AI COMPLIANCE AUDIT REPORT');
  lines.push('═══════════════════════════════════════════════════════');
  lines.push(`Transaction: ${folderName}`);
  lines.push(`Audited by: ${submittedBy}`);
  lines.push(`Date: ${auditDate}`);
  lines.push(`Type: ${conditions.transactionType}`);
  lines.push('');
  lines.push(`${riskEmoji[report.overallRisk] || '🟡'} ${riskLabel[report.overallRisk] || report.overallRisk}`);
  lines.push('');
  lines.push('SUMMARY');
  lines.push('───────────────────────────────────────────────────────');
  lines.push(report.summary);
  lines.push('');

  if (report.trueRisk && report.trueRisk.length > 0) {
    lines.push('🔴 TRUE RISK — ACTION REQUIRED BEFORE COE');
    lines.push('───────────────────────────────────────────────────────');
    for (const item of report.trueRisk) {
      lines.push(`• ${item.item} [${item.folder}]`);
      lines.push(`  Finding: ${item.detail}`);
      if (item.evidence) lines.push(`  Evidence: ${item.evidence}`);
      lines.push('');
    }
  }

  if (report.manageable && report.manageable.length > 0) {
    lines.push('🟡 MANAGEABLE — VERIFY BEFORE COE');
    lines.push('───────────────────────────────────────────────────────');
    for (const item of report.manageable) {
      lines.push(`• ${item.item} [${item.folder}]`);
      lines.push(`  Finding: ${item.detail}`);
      if (item.evidence) lines.push(`  Evidence: ${item.evidence}`);
      lines.push('');
    }
  }

  if (report.clear && report.clear.length > 0) {
    lines.push('✅ CLEAR — CONFIRMED PRESENT');
    lines.push('───────────────────────────────────────────────────────');
    for (const item of report.clear) {
      lines.push(`• ${item.item} [${item.folder}]`);
      if (item.evidence) lines.push(`  Evidence: ${item.evidence}`);
      lines.push('');
    }
  }

  if (report.crossReferenceFindings && report.crossReferenceFindings.length > 0) {
    lines.push('🔍 CROSS-REFERENCE CHECKS');
    lines.push('───────────────────────────────────────────────────────');
    for (const check of report.crossReferenceFindings) {
      const icon = check.result === 'PASS' ? '✅' : check.result === 'FAIL' ? '🔴' : '🟡';
      lines.push(`${icon} ${check.check}: ${check.result}`);
      if (check.detail) lines.push(`   ${check.detail}`);
      lines.push('');
    }
  }

  lines.push('───────────────────────────────────────────────────────');
  lines.push(report.disclaimer || 'Agent review required before COE.');
  lines.push('═══════════════════════════════════════════════════════');
  lines.push('SZ Real Estate Group · DRE #02066500');
  lines.push('Samuel K. Zieour, Realtor · Co-Founder & Team Lead · DRE #01397303');

  return lines.join('\n');
}

