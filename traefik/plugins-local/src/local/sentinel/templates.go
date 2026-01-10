// Package sentinel - HTML templates for error pages
package sentinel

const templateIPBlocked = `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Access Restricted</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #21232a; color: #e4e6eb; min-height: 100vh; display: flex; align-items: center; justify-content: center; padding: 20px; }
        .container { text-align: center; max-width: 480px; }
        .shield-wrapper { margin-bottom: 30px; display: inline-block; position: relative; }
        .shield { width: 90px; height: 108px; background: linear-gradient(180deg, #dc2626 0%, #991b1b 100%); clip-path: polygon(50% 0%, 100% 25%, 100% 75%, 50% 100%, 0% 75%, 0% 25%); position: relative; box-shadow: 0 0 50px rgba(220, 38, 38, 0.3); }
        .shield::before { content: ''; position: absolute; top: 4px; left: 4px; right: 4px; bottom: 4px; background: #21232a; clip-path: polygon(50% 2%, 98% 26%, 98% 74%, 50% 98%, 2% 74%, 2% 26%); }
        .shield-icon { position: absolute; top: 50%; left: 50%; transform: translate(-50%, -50%); font-size: 32px; z-index: 2; }
        .pulse-ring { position: absolute; top: 50%; left: 50%; transform: translate(-50%, -50%); width: 120px; height: 140px; border: 2px solid rgba(220, 38, 38, 0.4); border-radius: 50%; animation: pulse 2s ease-out infinite; }
        .pulse-ring:nth-child(2) { animation-delay: 0.5s; }
        @keyframes pulse { 0% { transform: translate(-50%, -50%) scale(0.8); opacity: 1; } 100% { transform: translate(-50%, -50%) scale(1.4); opacity: 0; } }
        .status-code { font-size: 14px; color: #ef4444; text-transform: uppercase; letter-spacing: 3px; margin-bottom: 15px; font-weight: 600; }
        h1 { font-size: 30px; font-weight: 600; margin-bottom: 12px; color: #fff; }
        .subtitle { font-size: 17px; color: #9ca3af; margin-bottom: 30px; line-height: 1.5; }
        .info-box { background: rgba(220, 38, 38, 0.08); border: 1px solid rgba(220, 38, 38, 0.25); border-radius: 12px; padding: 20px 25px; margin: 25px 0; }
        .info-row { display: flex; justify-content: space-between; align-items: center; padding: 8px 0; }
        .info-row:not(:last-child) { border-bottom: 1px solid rgba(220, 38, 38, 0.15); }
        .info-label { color: #9ca3af; font-size: 14px; }
        .info-value { color: #fca5a5; font-family: monospace; font-size: 14px; }
        .warning-text { background: linear-gradient(90deg, transparent, rgba(220, 38, 38, 0.1), transparent); padding: 15px; margin-top: 25px; border-radius: 8px; }
        .warning-text p { color: #f87171; font-size: 13px; display: flex; align-items: center; justify-content: center; gap: 8px; }
        .footer { margin-top: 35px; font-size: 13px; color: #6b7280; }
    </style>
</head>
<body>
    <div class="container">
        <div class="shield-wrapper">
            <div class="pulse-ring"></div>
            <div class="pulse-ring"></div>
            <div class="shield"></div>
            <span class="shield-icon">&#128274;</span>
        </div>
        <div class="status-code">Status {CODE}</div>
        <h1>Access Restricted</h1>
        <p class="subtitle">This resource is only accessible from authorized networks</p>
        <div class="info-box">
            <div class="info-row">
                <span class="info-label">Access Policy</span>
                <span class="info-value">IP Allowlist</span>
            </div>
            <div class="info-row">
                <span class="info-label">Status</span>
                <span class="info-value">Not Authorized</span>
            </div>
        </div>
        <div class="warning-text">
            <p>&#9888; Your network is not permitted to access this resource</p>
        </div>
        <p class="footer">Contact your administrator if you believe this is an error</p>
    </div>
</body>
</html>`

const templateUserAgent = `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Access Denied</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #21232a; color: #e4e6eb; min-height: 100vh; display: flex; align-items: center; justify-content: center; padding: 20px; }
        .container { text-align: center; max-width: 500px; }
        .robot-wrapper { margin-bottom: 30px; display: inline-block; }
        .robot { width: 100px; height: 100px; position: relative; }
        .robot-head { width: 70px; height: 55px; background: linear-gradient(180deg, #4b5563 0%, #374151 100%); border-radius: 12px; position: absolute; top: 15px; left: 50%; transform: translateX(-50%); border: 3px solid #6b7280; }
        .robot-eye { width: 14px; height: 14px; background: #ef4444; border-radius: 50%; position: absolute; top: 15px; animation: blink 3s ease-in-out infinite; box-shadow: 0 0 10px #ef4444; }
        .robot-eye.left { left: 12px; }
        .robot-eye.right { right: 12px; animation-delay: 0.1s; }
        @keyframes blink { 0%, 90%, 100% { transform: scaleY(1); } 95% { transform: scaleY(0.1); } }
        .robot-mouth { position: absolute; bottom: 10px; left: 50%; transform: translateX(-50%); width: 30px; height: 4px; background: #ef4444; border-radius: 2px; }
        .robot-antenna { width: 4px; height: 15px; background: #6b7280; position: absolute; top: 0; left: 50%; transform: translateX(-50%); border-radius: 2px; }
        .robot-antenna::after { content: ''; position: absolute; top: -8px; left: 50%; transform: translateX(-50%); width: 10px; height: 10px; background: #f59e0b; border-radius: 50%; animation: glow 1.5s ease-in-out infinite alternate; }
        @keyframes glow { from { box-shadow: 0 0 5px #f59e0b; } to { box-shadow: 0 0 15px #f59e0b; } }
        .robot-ear { width: 8px; height: 20px; background: #4b5563; border: 2px solid #6b7280; border-radius: 3px; position: absolute; top: 30px; }
        .robot-ear.left { left: 7px; }
        .robot-ear.right { right: 7px; }
        .no-symbol { position: absolute; top: 50%; left: 50%; transform: translate(-50%, -50%); width: 110px; height: 110px; border: 4px solid #ef4444; border-radius: 50%; opacity: 0.9; }
        .no-symbol::after { content: ''; position: absolute; top: 50%; left: -5px; width: 115px; height: 4px; background: #ef4444; transform: rotate(-45deg); transform-origin: center; }
        .status-code { font-size: 14px; color: #f59e0b; text-transform: uppercase; letter-spacing: 3px; margin-bottom: 15px; font-weight: 600; }
        h1 { font-size: 30px; font-weight: 600; margin-bottom: 12px; color: #fff; }
        .subtitle { font-size: 17px; color: #9ca3af; margin-bottom: 25px; line-height: 1.5; }
        .message-box { background: rgba(245, 158, 11, 0.08); border: 1px solid rgba(245, 158, 11, 0.25); border-radius: 12px; padding: 20px 25px; margin: 25px 0; }
        .code-text { font-family: monospace; color: #fcd34d; font-size: 13px; background: rgba(0,0,0,0.3); padding: 10px 15px; border-radius: 6px; display: inline-block; }
        .beep-boop { margin-top: 20px; font-size: 14px; color: #6b7280; font-style: italic; }
        .footer { margin-top: 30px; font-size: 13px; color: #6b7280; }
    </style>
</head>
<body>
    <div class="container">
        <div class="robot-wrapper">
            <div class="robot">
                <div class="robot-antenna"></div>
                <div class="robot-ear left"></div>
                <div class="robot-ear right"></div>
                <div class="robot-head">
                    <div class="robot-eye left"></div>
                    <div class="robot-eye right"></div>
                    <div class="robot-mouth"></div>
                </div>
            </div>
            <div class="no-symbol"></div>
        </div>
        <div class="status-code">Status {CODE}</div>
        <h1>Beep Boop... Access Denied</h1>
        <p class="subtitle">Automated access to this resource is not permitted</p>
        <div class="message-box">
            <p class="code-text">ERROR: Bot detected &#129302;</p>
            <p class="beep-boop">"I'm sorry, Dave. I'm afraid I can't do that."</p>
        </div>
        <p class="footer">If you're a human, try using a standard web browser</p>
    </div>
</body>
</html>`

const templateHeaderMissing = `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Authentication Required</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #21232a; color: #e4e6eb; min-height: 100vh; display: flex; align-items: center; justify-content: center; padding: 20px; }
        .container { text-align: center; max-width: 520px; }
        .key-wrapper { margin-bottom: 30px; display: inline-block; position: relative; }
        .key-icon { width: 100px; height: 100px; position: relative; }
        .key-head { width: 45px; height: 45px; border: 6px solid #10b981; border-radius: 50%; position: absolute; top: 10px; left: 10px; box-shadow: 0 0 30px rgba(16, 185, 129, 0.3); }
        .key-head::before { content: ''; position: absolute; top: 50%; left: 50%; transform: translate(-50%, -50%); width: 15px; height: 15px; border: 4px solid #10b981; border-radius: 50%; }
        .key-shaft { width: 50px; height: 8px; background: linear-gradient(90deg, #10b981, #059669); position: absolute; top: 50%; right: 5px; transform: translateY(-50%); border-radius: 0 4px 4px 0; }
        .key-teeth { position: absolute; right: 5px; top: calc(50% + 4px); display: flex; gap: 4px; }
        .tooth { width: 6px; height: 12px; background: #10b981; border-radius: 0 0 2px 2px; }
        .tooth:nth-child(1) { height: 14px; }
        .tooth:nth-child(2) { height: 10px; }
        .tooth:nth-child(3) { height: 16px; }
        .lock-overlay { position: absolute; top: 50%; left: 50%; transform: translate(-50%, -50%); font-size: 20px; background: #21232a; padding: 5px 10px; border-radius: 6px; border: 2px dashed rgba(16, 185, 129, 0.5); }
        .scan-line { position: absolute; top: 0; left: 0; right: 0; height: 2px; background: linear-gradient(90deg, transparent, #10b981, transparent); animation: scan 2s linear infinite; }
        @keyframes scan { 0% { top: 0; opacity: 1; } 100% { top: 100px; opacity: 0; } }
        .status-code { font-size: 14px; color: #10b981; text-transform: uppercase; letter-spacing: 3px; margin-bottom: 15px; font-weight: 600; }
        h1 { font-size: 30px; font-weight: 600; margin-bottom: 12px; color: #fff; }
        .subtitle { font-size: 17px; color: #9ca3af; margin-bottom: 25px; }
        .tech-box { background: linear-gradient(180deg, rgba(16, 185, 129, 0.08) 0%, rgba(16, 185, 129, 0.02) 100%); border: 1px solid rgba(16, 185, 129, 0.25); border-radius: 12px; padding: 20px 25px; margin: 25px 0; text-align: left; }
        .tech-header { display: flex; align-items: center; gap: 10px; margin-bottom: 15px; padding-bottom: 12px; border-bottom: 1px solid rgba(16, 185, 129, 0.15); }
        .tech-icon { font-size: 18px; }
        .tech-title { font-size: 14px; color: #34d399; font-weight: 600; text-transform: uppercase; letter-spacing: 1px; }
        .requirement-list { list-style: none; }
        .requirement-list li { padding: 8px 0; color: #9ca3af; font-size: 14px; display: flex; align-items: center; gap: 10px; }
        .requirement-list li::before { content: '>'; color: #10b981; font-family: monospace; font-weight: bold; }
        .requirement-list code { background: rgba(0, 0, 0, 0.3); padding: 2px 8px; border-radius: 4px; color: #6ee7b7; font-family: monospace; font-size: 13px; }
        .footer { margin-top: 30px; font-size: 13px; color: #6b7280; }
    </style>
</head>
<body>
    <div class="container">
        <div class="key-wrapper">
            <div class="key-icon">
                <div class="key-head"></div>
                <div class="key-shaft"></div>
                <div class="key-teeth">
                    <div class="tooth"></div>
                    <div class="tooth"></div>
                    <div class="tooth"></div>
                </div>
                <div class="scan-line"></div>
            </div>
            <div class="lock-overlay">&#128272;</div>
        </div>
        <div class="status-code">Status {CODE}</div>
        <h1>Authentication Required</h1>
        <p class="subtitle">This request is missing required authentication credentials</p>
        <div class="tech-box">
            <div class="tech-header">
                <span class="tech-icon">&#128736;</span>
                <span class="tech-title">Technical Details</span>
            </div>
            <ul class="requirement-list">
                <li>Required header is missing or invalid</li>
                <li>Ensure proper <code>Authorization</code> header is set</li>
                <li>Verify credentials have not expired</li>
            </ul>
        </div>
        <p class="footer">Need help? Contact your system administrator</p>
    </div>
</body>
</html>`

const templateTimeAccess = `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Access Not Available</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #21232a; color: #e4e6eb; min-height: 100vh; display: flex; align-items: center; justify-content: center; padding: 20px; }
        .container { text-align: center; max-width: 520px; }
        .clock-wrapper { margin-bottom: 30px; display: inline-block; }
        .clock { width: 100px; height: 100px; border: 4px solid #6366f1; border-radius: 50%; position: relative; background: linear-gradient(180deg, rgba(99, 102, 241, 0.1) 0%, rgba(99, 102, 241, 0.05) 100%); box-shadow: 0 0 50px rgba(99, 102, 241, 0.25); }
        .clock::before { content: ''; position: absolute; top: 50%; left: 50%; width: 8px; height: 8px; background: #6366f1; border-radius: 50%; transform: translate(-50%, -50%); z-index: 3; }
        .hand { position: absolute; bottom: 50%; left: 50%; transform-origin: bottom center; background: #6366f1; border-radius: 2px; }
        .hour-hand { width: 4px; height: 25px; transform: translateX(-50%) rotate(45deg); }
        .minute-hand { width: 3px; height: 35px; transform: translateX(-50%) rotate(180deg); animation: tick 60s steps(60) infinite; }
        @keyframes tick { to { transform: translateX(-50%) rotate(540deg); } }
        .status-code { font-size: 14px; color: #6366f1; text-transform: uppercase; letter-spacing: 3px; margin-bottom: 15px; font-weight: 600; }
        h1 { font-size: 30px; font-weight: 600; margin-bottom: 12px; color: #fff; }
        .subtitle { font-size: 17px; color: #9ca3af; margin-bottom: 30px; }
        .schedule-card { background: linear-gradient(135deg, rgba(99, 102, 241, 0.15) 0%, rgba(99, 102, 241, 0.05) 100%); border: 1px solid rgba(99, 102, 241, 0.3); border-radius: 16px; padding: 25px 30px; margin: 20px 0; }
        .schedule-label { font-size: 12px; color: #8b8fa3; text-transform: uppercase; letter-spacing: 2px; margin-bottom: 10px; }
        .schedule-time { font-size: 28px; font-weight: 700; color: #a5b4fc; font-family: monospace; letter-spacing: 1px; }
        .timezone-info { display: flex; align-items: center; justify-content: center; gap: 8px; margin-top: 15px; padding-top: 15px; border-top: 1px solid rgba(99, 102, 241, 0.2); }
        .timezone-text { color: #9ca3af; font-size: 14px; }
        .timezone-value { color: #c7d2fe; font-weight: 500; }
        .hint { margin-top: 30px; font-size: 14px; color: #6b7280; }
    </style>
</head>
<body>
    <div class="container">
        <div class="clock-wrapper">
            <div class="clock">
                <div class="hand hour-hand"></div>
                <div class="hand minute-hand"></div>
            </div>
        </div>
        <div class="status-code">Status {CODE}</div>
        <h1>Outside Access Hours</h1>
        <p class="subtitle">This resource is only available during scheduled hours</p>
        <div class="schedule-card">
            <p class="schedule-label">Access Window</p>
            <p class="schedule-time">Check with admin</p>
            <div class="timezone-info">
                <span class="timezone-text">Please return during scheduled hours</span>
            </div>
        </div>
        <p class="hint">Contact your administrator for access schedule</p>
    </div>
</body>
</html>`

const templateMaintenance = `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Under Maintenance</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #21232a; color: #e4e6eb; min-height: 100vh; display: flex; align-items: center; justify-content: center; padding: 20px; }
        .container { text-align: center; max-width: 500px; }
        .icon-wrapper { margin-bottom: 30px; position: relative; display: inline-block; }
        .gear { width: 80px; height: 80px; background: linear-gradient(135deg, #f5a623 0%, #f7931e 100%); border-radius: 50%; position: relative; animation: spin 8s linear infinite; box-shadow: 0 0 40px rgba(245, 166, 35, 0.3); }
        .gear::before { content: ''; position: absolute; top: 50%; left: 50%; transform: translate(-50%, -50%); width: 30px; height: 30px; background: #21232a; border-radius: 50%; }
        .gear::after { content: ''; position: absolute; top: -8px; left: 50%; transform: translateX(-50%); width: 16px; height: 96px; background: linear-gradient(135deg, #f5a623 0%, #f7931e 100%); border-radius: 4px; }
        .wrench { position: absolute; top: 50%; left: 50%; transform: translate(-50%, -50%) rotate(-45deg); font-size: 36px; color: #21232a; z-index: 2; }
        @keyframes spin { from { transform: rotate(0deg); } to { transform: rotate(360deg); } }
        .status-code { font-size: 14px; color: #f5a623; text-transform: uppercase; letter-spacing: 3px; margin-bottom: 15px; font-weight: 600; }
        h1 { font-size: 32px; font-weight: 600; margin-bottom: 15px; color: #fff; }
        .subtitle { font-size: 18px; color: #9ca3af; margin-bottom: 25px; }
        .message-box { background: rgba(245, 166, 35, 0.1); border: 1px solid rgba(245, 166, 35, 0.3); border-radius: 12px; padding: 20px; margin: 25px 0; }
        .message-box p { color: #f5d69c; line-height: 1.6; }
        .progress-bar { width: 100%; height: 4px; background: #3a3d47; border-radius: 2px; overflow: hidden; margin-top: 30px; }
        .progress-bar::after { content: ''; display: block; width: 30%; height: 100%; background: linear-gradient(90deg, #f5a623, #f7931e); border-radius: 2px; animation: progress 2s ease-in-out infinite; }
        @keyframes progress { 0% { transform: translateX(-100%); } 100% { transform: translateX(400%); } }
        .footer { margin-top: 40px; font-size: 13px; color: #6b7280; }
    </style>
</head>
<body>
    <div class="container">
        <div class="icon-wrapper">
            <div class="gear"></div>
            <span class="wrench">&#128295;</span>
        </div>
        <div class="status-code">Status {CODE}</div>
        <h1>We'll Be Back Soon</h1>
        <p class="subtitle">This service is currently undergoing scheduled maintenance</p>
        <div class="message-box">
            <p>{MESSAGE}</p>
        </div>
        <div class="progress-bar"></div>
        <p class="footer">Thank you for your patience</p>
    </div>
</body>
</html>`
