# Phishing-Email-Investigation-in-Microsoft-Defender-eDiscovery-Microsoft-Purview-
This guide explains how to investigate a **OneDrive-themed phishing email** using **Microsoft Defender for Office 365** and how to create an **eDiscovery case** in **Microsoft Purview**.

# Phishing Email Investigation in Microsoft Defender + eDiscovery (Microsoft Purview)

This guide explains how to investigate a **OneDrive-themed phishing email** using **Microsoft Defender for Office 365** and how to create an **eDiscovery case** in **Microsoft Purview**.

**Scenario used in this guide**
- **Subject:** Your file will be deleted  
- **Fake sender:** onedrive-notify@micr0soft-secure[.]co  
- **Theme:** OneDrive file deletion / urgency phishing

---

## Prerequisites
- Access to:
  - Microsoft Defender: https://security.microsoft.com
  - Microsoft Purview: https://compliance.microsoft.com
- Roles:
  - Security Operator / Security Admin (Defender)
  - eDiscovery Manager (Standard or Premium)

---

## Part 1: Investigating the Phishing Email in Microsoft Defender

### 1. Initial triage
Collect the following:
- Subject: **Your file will be deleted**
- Sender: `onedrive-notify@micr0soft-secure[.]co`
- Reported URL (usually “View file” or “Keep my files”)
- Time received
- User(s) reporting the email

---

### 2. Find recipients (who received it)

#### Defender Explorer
1. Go to **Email & collaboration → Explorer**
2. Filter:
   - **Subject contains:** `Your file will be deleted`
3. Review:
   - Recipient list
   - Delivery location (Inbox/Junk)
   - Delivery action

---

### 3. Check who clicked the phishing link

#### URL Trace (Safe Links)
1. **Email & collaboration → Review → URL trace**
2. Paste the suspicious URL or domain
3. Set date range
4. Review:
   - Users who clicked
   - Number of clicks
   - Timestamp
   - Allowed vs blocked

---

### 4. Check attachments (if present)
1. Open the email in **Explorer**
2. Review attachment name and type
3. Pivot to **EmailAttachmentInfo** if needed

---

### 5. Remove the email from all mailboxes (Remediation)

1. In **Explorer**, select the message
2. Choose **Actions → Soft delete**

**Result**
- Email removed from Inbox
- Not visible to users
- Retained in hidden recoverable storage (admin-only)

---

### 6. Block future attempts
- Block sender domain: `micr0soft-secure[.]co`
- Block URL/domain if confirmed malicious
- Review anti-phishing policy (OneDrive impersonation)

---

## Part 2: Advanced Hunting (KQL)

### A. Find the phishing email by subject
```kql
EmailEvents
| where Timestamp between (datetime(2026-02-01) .. datetime(2026-03-01))
| where Subject has "Your file will be deleted"
| project Timestamp, RecipientEmailAddress, Subject, NetworkMessageId, DeliveryAction, DeliveryLocation
| order by Timestamp desc

B. Find link clicks
EmailUrlInfo
| where Timestamp between (datetime(2026-02-01) .. datetime(2026-03-01))
| where Url has_any ("onedrive", "sharepoint", "login")
| project Timestamp, RecipientEmailAddress, Url, NetworkMessageId
| order by Timestamp desc


C. Attachments (if applicable)
EmailAttachmentInfo
| where Timestamp between (datetime(2026-02-01) .. datetime(2026-03-01))
| project Timestamp, RecipientEmailAddress, FileName, FileType, SHA256
| order by Timestamp desc



