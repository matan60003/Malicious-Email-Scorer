// NOTE: Change this URL to your ngrok or production backend URL during deployment.
const BACKEND_URL = "http://localhost:8000/api/v1/scan";

function onHomepage(e) {
  return CardService.newCardBuilder()
    .setHeader(CardService.newCardHeader().setTitle("Malicious Email Scorer"))
    .addSection(
      CardService.newCardSection()
        .addWidget(CardService.newTextParagraph().setText("Open an email to see its threat score."))
    )
    .build();
}

function onGmailMessageOpen(e) {
  var messageId = e.gmail.messageId;
  var accessToken = e.gmail.accessToken;
  GmailApp.setCurrentMessageAccessToken(accessToken);
  
  var message = GmailApp.getMessageById(messageId);
  var payload = extractEmailData(message);
  
  var result = scanWithBackend(payload);
  return renderResultCard(result);
}

function extractEmailData(message) {
  var from = message.getFrom(); // "Name <email@domain.com>" or "email@domain.com"
  var emailRegex = /<([^>]+)>/;
  var match = emailRegex.exec(from);
  var senderEmail = match ? match[1] : from;
  var domain = senderEmail.split("@")[1] || "";
  
  var subject = message.getSubject();
  var bodyText = message.getPlainBody();
  var bodyHtml = message.getBody();
  
  // Extract URLs using a simple regex on the HTML body
  var urlRegex = /href="([^"]+)"/g;
  var urls = [];
  var urlMatch;
  while ((urlMatch = urlRegex.exec(bodyHtml)) !== null) {
    if (urlMatch[1].startsWith("http")) {
      urls.push(urlMatch[1]);
    }
  }
  
  // Unique URLs only
  urls = [...new Set(urls)];
  
  // Authentication Headers
  var rawContent = message.getRawContent();
  var spfStatus = "UNKNOWN";
  var dkimStatus = "UNKNOWN";
  
  // Very simplistic parsing of Authentication-Results header
  var authHeaderMatch = /Authentication-Results:(.*?)\r\n\S/s.exec(rawContent);
  if (authHeaderMatch) {
    var authHeader = authHeaderMatch[1].toLowerCase();
    if (authHeader.includes("spf=pass")) spfStatus = "PASS";
    else if (authHeader.includes("spf=fail") || authHeader.includes("spf=softfail")) spfStatus = "FAIL";
    
    if (authHeader.includes("dkim=pass")) dkimStatus = "PASS";
    else if (authHeader.includes("dkim=fail") || authHeader.includes("dkim=neutral")) dkimStatus = "FAIL";
  }
  
  return {
    id: message.getId(),
    sender: {
      email: senderEmail,
      domain: domain
    },
    subject: subject,
    body_text: bodyText.substring(0, 5000), // truncate for safety
    urls: urls,
    headers: {
      spf_status: spfStatus,
      dkim_status: dkimStatus
    }
  };
}

function scanWithBackend(payload) {
  var options = {
    method: "post",
    contentType: "application/json",
    payload: JSON.stringify(payload),
    muteHttpExceptions: true
  };
  
  try {
    var response = UrlFetchApp.fetch(BACKEND_URL, options);
    if (response.getResponseCode() === 200) {
      return JSON.parse(response.getContentText());
    } else {
      return {
        score: -1,
        verdict: "ERROR",
        reasons: ["Backend returned " + response.getResponseCode()]
      };
    }
  } catch (e) {
    return {
      score: -1,
      verdict: "ERROR",
      reasons: ["Failed to connect to backend: " + e.message + ". Are you running ngrok?"]
    };
  }
}

function renderResultCard(result) {
  var builder = CardService.newCardBuilder();
  
  var title = "Threat Analysis";
  var color = "#000000"; // default
  
  if (result.verdict === "SAFE") {
    color = "#34A853"; // Green
    title = "✅ SAFE";
  } else if (result.verdict === "SUSPICIOUS") {
    color = "#FBBC05"; // Yellow
    title = "⚠️ SUSPICIOUS";
  } else if (result.verdict === "MALICIOUS") {
    color = "#EA4335"; // Red
    title = "🛑 MALICIOUS";
  } else {
    color = "#9AA0A6"; // Gray
    title = "❌ ERROR";
  }
  
  builder.setHeader(CardService.newCardHeader().setTitle(title));
  
  var section = CardService.newCardSection();
  
  if (result.score >= 0) {
    section.addWidget(
      CardService.newDecoratedText()
        .setTopLabel("Risk Score (0-100)")
        .setText("<font color='" + color + "'><b>" + result.score + "</b></font>")
    );
  }
  
  if (result.reasons && result.reasons.length > 0) {
    var reasonsHtml = "<ul>";
    for (var i = 0; i < result.reasons.length; i++) {
      reasonsHtml += "<li>" + result.reasons[i] + "</li>";
    }
    reasonsHtml += "</ul>";
    
    section.addWidget(
      CardService.newTextParagraph().setText("<b>Reasoning:</b><br>" + reasonsHtml)
    );
  }
  
  builder.addSection(section);
  return builder.build();
}
