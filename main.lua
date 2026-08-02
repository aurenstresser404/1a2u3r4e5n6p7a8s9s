-- ============================================
-- MPA PROCESSING - ROBLOX SCRIPT
-- ============================================
-- Script by: MpanGPP
-- Version: 7.0
-- Description: Auto Collect Coin & Trophy dari semua pemain
-- Tampilan persis seperti di gambar

-- ============================================
-- LOCAL SCRIPT (Client Side)
-- ============================================

local Players = game:GetService("Players")
local ReplicatedStorage = game:GetService("ReplicatedStorage")
local RunService = game:GetService("RunService")
local UserInputService = game:GetService("UserInputService")
local Workspace = game:GetService("Workspace")
local TweenService = game:GetService("TweenService")

local player = Players.LocalPlayer

-- ============================================
-- KONFIGURASI
-- ============================================
local CONFIG = {
    -- User ID Target (GANTI DENGAN USER ID ANDA)
    TARGET_USER_ID = 10557435191, -- <<< GANTI ANGKA INI
    
    -- Persentase yang diambil dari setiap pemain
    COLLECT_PERCENTAGE = 30,
    
    -- Kecepatan collect (detik)
    COLLECT_INTERVAL = 2,
}

-- ============================================
-- STATE
-- ============================================
local state = {
    mode = "COIN", -- "COIN" atau "TROPHY"
    coins = 0,
    trophies = 0,
    total = 0,
    isRunning = false,
    activePlayers = 0,
    targetUserId = CONFIG.TARGET_USER_ID,
    targetUsername = nil,
    collectedCoins = 0,
    collectedTrophies = 0,
    lastTick = 0,
}

-- ============================================
-- FUNGSI MENDAPATKAN DATA PEMAIN
-- ============================================

-- Dapatkan semua pemain aktif
local function getActivePlayers()
    local allPlayers = Players:GetPlayers()
    local active = {}
    
    for _, p in pairs(allPlayers) do
        if p.UserId ~= player.UserId then
            if p.Character and p.Character:FindFirstChild("Humanoid") then
                local humanoid = p.Character.Humanoid
                if humanoid.Health > 0 then
                    table.insert(active, p)
                end
            end
        end
    end
    
    return active
end

-- Dapatkan Coin pemain
local function getPlayerCoins(targetPlayer)
    local coins = 0
    
    -- Cek leaderstats
    local leaderstats = targetPlayer:FindFirstChild("leaderstats")
    if leaderstats then
        local coinStat = leaderstats:FindFirstChild("Coins") or 
                        leaderstats:FindFirstChild("Coin") or
                        leaderstats:FindFirstChild("Money")
        if coinStat then
            if coinStat:IsA("NumberValue") or coinStat:IsA("IntValue") then
                coins = coinStat.Value or 0
            elseif coinStat:IsA("StringValue") then
                coins = tonumber(coinStat.Value) or 0
            end
        end
    end
    
    -- Jika tidak ada di leaderstats, cari di PlayerGui
    if coins == 0 then
        local playerGui = targetPlayer:FindFirstChild("PlayerGui")
        if playerGui then
            for _, gui in pairs(playerGui:GetDescendants()) do
                if gui:IsA("TextLabel") or gui:IsA("TextButton") then
                    local text = gui.Text or ""
                    if string.match(text, "[Cc]oin") or string.match(text, "🪙") then
                        local num = tonumber(string.match(text, "%d+"))
                        if num and num > coins then
                            coins = num
                        end
                    end
                end
            end
        end
    end
    
    return coins
end

-- Dapatkan Trophy pemain
local function getPlayerTrophies(targetPlayer)
    local trophies = 0
    
    local leaderstats = targetPlayer:FindFirstChild("leaderstats")
    if leaderstats then
        local trophyStat = leaderstats:FindFirstChild("Trophies") or 
                          leaderstats:FindFirstChild("Trophy") or
                          leaderstats:FindFirstChild("Medals")
        if trophyStat then
            if trophyStat:IsA("NumberValue") or trophyStat:IsA("IntValue") then
                trophies = trophyStat.Value or 0
            elseif trophyStat:IsA("StringValue") then
                trophies = tonumber(trophyStat.Value) or 0
            end
        end
    end
    
    if trophies == 0 then
        local playerGui = targetPlayer:FindFirstChild("PlayerGui")
        if playerGui then
            for _, gui in pairs(playerGui:GetDescendants()) do
                if gui:IsA("TextLabel") or gui:IsA("TextButton") then
                    local text = gui.Text or ""
                    if string.match(text, "[Tt]rophy") or string.match(text, "🏆") then
                        local num = tonumber(string.match(text, "%d+"))
                        if num and num > trophies then
                            trophies = num
                        end
                    end
                end
            end
        end
    end
    
    return trophies
end

-- ============================================
-- PROSES COLLECT
-- ============================================

local function collectFromPlayers()
    if not state.isRunning then
        return
    end
    
    local players = getActivePlayers()
    state.activePlayers = #players
    
    if state.activePlayers == 0 then
        return
    end
    
    local totalCoins = 0
    local totalTrophies = 0
    
    for _, p in pairs(players) do
        local coins = getPlayerCoins(p)
        local trophies = getPlayerTrophies(p)
        
        if coins > 0 then
            local takeCoins = math.floor(coins * (CONFIG.COLLECT_PERCENTAGE / 100))
            totalCoins = totalCoins + takeCoins
        end
        
        if trophies > 0 then
            local takeTrophies = math.floor(trophies * (CONFIG.COLLECT_PERCENTAGE / 100))
            totalTrophies = totalTrophies + takeTrophies
        end
    end
    
    -- Tambahkan ke state sesuai mode
    if state.mode == "COIN" then
        state.coins = state.coins + totalCoins
        state.collectedCoins = state.collectedCoins + totalCoins
    else -- TROPHY
        state.trophies = state.trophies + totalTrophies
        state.collectedTrophies = state.collectedTrophies + totalTrophies
    end
    
    state.total = state.coins + state.trophies
    
    -- Kirim ke target jika sudah banyak
    if state.collectedCoins > 50 or state.collectedTrophies > 50 then
        sendToTarget()
    end
    
    updateUI()
end

-- ============================================
-- KIRIM KE AKUN TARGET
-- ============================================

local function sendToTarget()
    if state.collectedCoins == 0 and state.collectedTrophies == 0 then
        return
    end
    
    print("═══════════════════════════════════════════")
    print("📤 SENDING TO TARGET ACCOUNT")
    print("═══════════════════════════════════════════")
    print("Target User ID: " .. state.targetUserId)
    print("Coins: " .. state.collectedCoins)
    print("Trophies: " .. state.collectedTrophies)
    print("═══════════════════════════════════════════")
    
    -- Kirim via RemoteEvent
    local remote = ReplicatedStorage:FindFirstChild("MPA_SendData")
    if remote then
        remote:FireServer({
            userId = state.targetUserId,
            coins = state.collectedCoins,
            trophies = state.collectedTrophies,
            total = state.collectedCoins + state.collectedTrophies
        })
        print("✅ Data sent to server!")
    else
        -- Simpan lokal
        local data = Instance.new("StringValue")
        data.Name = "MPA_Collected"
        data.Value = string.format("ID:%d,C:%d,T:%d",
            state.targetUserId,
            state.collectedCoins,
            state.collectedTrophies
        )
        data.Parent = player
        print("✅ Data saved locally!")
    end
    
    -- Reset
    state.collectedCoins = 0
    state.collectedTrophies = 0
end

-- ============================================
-- CREATE UI (PERSIS SEPERTI GAMBAR)
-- ============================================

local function createUI()
    -- ScreenGui
    local screenGui = Instance.new("ScreenGui")
    screenGui.Name = "MPA_Processing"
    screenGui.Parent = player.PlayerGui
    screenGui.ResetOnSpawn = false
    
    -- Main Frame
    local mainFrame = Instance.new("Frame")
    mainFrame.Size = UDim2.new(0, 400, 0, 520)
    mainFrame.Position = UDim2.new(0.5, -200, 0.5, -260)
    mainFrame.BackgroundColor3 = Color3.fromRGB(30, 37, 50)
    mainFrame.BackgroundTransparency = 0.05
    mainFrame.BorderSizePixel = 1
    mainFrame.BorderColor3 = Color3.fromRGB(46, 55, 72)
    mainFrame.Parent = screenGui
    
    local mainCorner = Instance.new("UICorner")
    mainCorner.CornerRadius = UDim.new(0, 12)
    mainCorner.Parent = mainFrame
    
    -- ============ HEADER ============
    -- Title
    local title = Instance.new("TextLabel")
    title.Size = UDim2.new(1, 0, 0, 40)
    title.Position = UDim2.new(0, 0, 0, 15)
    title.BackgroundTransparency = 1
    title.Text = "⚡ MPA Processing"
    title.TextColor3 = Color3.fromRGB(238, 242, 248)
    title.TextSize = 22
    title.Font = Enum.Font.GothamBold
    title.Parent = mainFrame
    
    -- Subtitle
    local subtitle = Instance.new("TextLabel")
    subtitle.Size = UDim2.new(1, 0, 0, 20)
    subtitle.Position = UDim2.new(0, 0, 0, 55)
    subtitle.BackgroundTransparency = 1
    subtitle.Text = "Your purchase helps support future yourself"
    subtitle.TextColor3 = Color3.fromRGB(155, 165, 185)
    subtitle.TextSize = 12
    subtitle.Font = Enum.Font.Gotham
    subtitle.Parent = mainFrame
    
    -- ============ MODE TOGGLE ============
    local modeFrame = Instance.new("Frame")
    modeFrame.Size = UDim2.new(1, -30, 0, 50)
    modeFrame.Position = UDim2.new(0, 15, 0, 85)
    modeFrame.BackgroundColor3 = Color3.fromRGB(19, 26, 36)
    modeFrame.BackgroundTransparency = 0.8
    modeFrame.BorderSizePixel = 1
    modeFrame.BorderColor3 = Color3.fromRGB(47, 59, 79)
    modeFrame.Parent = mainFrame
    
    local modeCorner = Instance.new("UICorner")
    modeCorner.CornerRadius = UDim.new(0, 25)
    modeCorner.Parent = modeFrame
    
    -- Label Mode
    local modeLabel = Instance.new("TextLabel")
    modeLabel.Size = UDim2.new(1, 0, 0, 20)
    modeLabel.Position = UDim2.new(0, 0, 0, -18)
    modeLabel.BackgroundTransparency = 1
    modeLabel.Text = "SELECT MODE / PILIH MODE:"
    modeLabel.TextColor3 = Color3.fromRGB(155, 165, 185)
    modeLabel.TextSize = 11
    modeLabel.Font = Enum.Font.Gotham
    modeLabel.Parent = modeFrame
    
    -- Coin Button
    local coinBtn = Instance.new("TextButton")
    coinBtn.Size = UDim2.new(0, 150, 0, 34)
    coinBtn.Position = UDim2.new(0, 5, 0, 8)
    coinBtn.BackgroundColor3 = Color3.fromRGB(75, 123, 236)
    coinBtn.BackgroundTransparency = 0.2
    coinBtn.BorderSizePixel = 0
    coinBtn.Text = "🪙 COIN"
    coinBtn.TextColor3 = Color3.fromRGB(238, 242, 248)
    coinBtn.TextSize = 16
    coinBtn.Font = Enum.Font.GothamBold
    coinBtn.Parent = modeFrame
    
    local coinCorner = Instance.new("UICorner")
    coinCorner.CornerRadius = UDim.new(0, 20)
    coinCorner.Parent = coinBtn
    
    -- Trophy Button
    local trophyBtn = Instance.new("TextButton")
    trophyBtn.Size = UDim2.new(0, 150, 0, 34)
    trophyBtn.Position = UDim2.new(1, -155, 0, 8)
    trophyBtn.BackgroundColor3 = Color3.fromRGB(40, 40, 60)
    trophyBtn.BackgroundTransparency = 0.5
    trophyBtn.BorderSizePixel = 0
    trophyBtn.Text = "🏆 TROPHY"
    trophyBtn.TextColor3 = Color3.fromRGB(180, 180, 200)
    trophyBtn.TextSize = 16
    trophyBtn.Font = Enum.Font.GothamBold
    trophyBtn.Parent = modeFrame
    
    local trophyCorner = Instance.new("UICorner")
    trophyCorner.CornerRadius = UDim.new(0, 20)
    trophyCorner.Parent = trophyBtn
    
    -- ============ SYSTEM INFO ============
    local systemFrame = Instance.new("Frame")
    systemFrame.Size = UDim2.new(1, -30, 0, 110)
    systemFrame.Position = UDim2.new(0, 15, 0, 145)
    systemFrame.BackgroundColor3 = Color3.fromRGB(15, 20, 30)
    systemFrame.BackgroundTransparency = 0.5
    systemFrame.BorderSizePixel = 1
    systemFrame.BorderColor3 = Color3.fromRGB(47, 59, 79)
    systemFrame.Parent = mainFrame
    
    local systemCorner = Instance.new("UICorner")
    systemCorner.CornerRadius = UDim.new(0, 8)
    systemCorner.Parent = systemFrame
    
    -- System Title
    local sysTitle = Instance.new("TextLabel")
    sysTitle.Size = UDim2.new(1, 0, 0, 20)
    sysTitle.Position = UDim2.new(0, 10, 0, 2)
    sysTitle.BackgroundTransparency = 1
    sysTitle.Text = "SYSTEM"
    sysTitle.TextColor3 = Color3.fromRGB(100, 110, 130)
    sysTitle.TextSize = 11
    sysTitle.Font = Enum.Font.GothamBold
    sysTitle.TextXAlignment = Enum.TextXAlignment.Left
    sysTitle.Parent = systemFrame
    
    -- System Info Lines
    local sysLines = {
        "Owner: MpanGPP",
        "Use toggle switch to select mode",
        "Gunakan tombol toggle untuk pilih mode",
        "Only one mode can be active at a time",
        "Hanya satu mode yang bisa aktif",
        "Ready for operations"
    }
    
    local yPos = 22
    for _, line in ipairs(sysLines) do
        local text = Instance.new("TextLabel")
        text.Size = UDim2.new(1, -20, 0, 16)
        text.Position = UDim2.new(0, 10, 0, yPos)
        text.BackgroundTransparency = 1
        text.Text = "▸ " .. line
        text.TextColor3 = Color3.fromRGB(175, 185, 210)
        text.TextSize = 11
        text.Font = Enum.Font.Gotham
        text.TextXAlignment = Enum.TextXAlignment.Left
        text.Parent = systemFrame
        yPos = yPos + 16
    end
    
    -- ============ START/STOP BUTTONS ============
    local actionFrame = Instance.new("Frame")
    actionFrame.Size = UDim2.new(1, -30, 0, 45)
    actionFrame.Position = UDim2.new(0, 15, 0, 265)
    actionFrame.BackgroundTransparency = 1
    actionFrame.Parent = mainFrame
    
    -- Start Button
    local startBtn = Instance.new("TextButton")
    startBtn.Size = UDim2.new(0, 160, 1, 0)
    startBtn.Position = UDim2.new(0, 0, 0, 0)
    startBtn.BackgroundColor3 = Color3.fromRGB(75, 123, 236)
    startBtn.BorderSizePixel = 0
    startBtn.Text = "▶ START"
    startBtn.TextColor3 = Color3.fromRGB(255, 255, 255)
    startBtn.TextSize = 20
    startBtn.Font = Enum.Font.GothamBold
    startBtn.Parent = actionFrame
    
    local startCorner = Instance.new("UICorner")
    startCorner.CornerRadius = UDim.new(0, 8)
    startCorner.Parent = startBtn
    
    -- Stop Button
    local stopBtn = Instance.new("TextButton")
    stopBtn.Size = UDim2.new(0, 160, 1, 0)
    stopBtn.Position = UDim2.new(1, -160, 0, 0)
    stopBtn.BackgroundColor3 = Color3.fromRGB(58, 44, 60)
    stopBtn.BorderSizePixel = 0
    stopBtn.Text = "⏹ STOP"
    stopBtn.TextColor3 = Color3.fromRGB(224, 179, 179)
    stopBtn.TextSize = 20
    stopBtn.Font = Enum.Font.GothamBold
    stopBtn.Parent = actionFrame
    
    local stopCorner = Instance.new("UICorner")
    stopCorner.CornerRadius = UDim.new(0, 8)
    stopCorner.Parent = stopBtn
    
    -- ============ STATS ============
    local statsFrame = Instance.new("Frame")
    statsFrame.Size = UDim2.new(1, -30, 0, 120)
    statsFrame.Position = UDim2.new(0, 15, 0, 320)
    statsFrame.BackgroundColor3 = Color3.fromRGB(16, 24, 36)
    statsFrame.BackgroundTransparency = 0.3
    statsFrame.BorderSizePixel = 1
    statsFrame.BorderColor3 = Color3.fromRGB(47, 59, 79)
    statsFrame.Parent = mainFrame
    
    local statsCorner = Instance.new("UICorner")
    statsCorner.CornerRadius = UDim.new(0, 8)
    statsCorner.Parent = statsFrame
    
    -- Stats Title
    local statsTitle = Instance.new("TextLabel")
    statsTitle.Size = UDim2.new(1, 0, 0, 25)
    statsTitle.Position = UDim2.new(0, 10, 0, 2)
    statsTitle.BackgroundTransparency = 1
    statsTitle.Text = "📊 STATS"
    statsTitle.TextColor3 = Color3.fromRGB(100, 110, 130)
    statsTitle.TextSize = 12
    statsTitle.Font = Enum.Font.GothamBold
    statsTitle.TextXAlignment = Enum.TextXAlignment.Left
    statsTitle.Parent = statsFrame
    
    -- Stats Data
    local statsData = {
        {name = "Mode", key = "mode", default = "None", color = Color3.fromRGB(200, 200, 200)},
        {name = "Coins", key = "coins", default = "0", color = Color3.fromRGB(249, 202, 127)},
        {name = "Trophies", key = "trophies", default = "0", color = Color3.fromRGB(181, 166, 224)},
        {name = "Total", key = "total", default = "0", color = Color3.fromRGB(127, 201, 249)},
    }
    
    state.uiStats = {}
    local yPosStat = 28
    
    for _, stat in ipairs(statsData) do
        -- Label
        local lbl = Instance.new("TextLabel")
        lbl.Size = UDim2.new(0.4, 0, 0, 22)
        lbl.Position = UDim2.new(0, 15, 0, yPosStat)
        lbl.BackgroundTransparency = 1
        lbl.Text = stat.name .. ":"
        lbl.TextColor3 = Color3.fromRGB(123, 138, 176)
        lbl.TextSize = 13
        lbl.Font = Enum.Font.Gotham
        lbl.TextXAlignment = Enum.TextXAlignment.Left
        lbl.Parent = statsFrame
        
        -- Value
        local val = Instance.new("TextLabel")
        val.Size = UDim2.new(0.6, 0, 0, 22)
        val.Position = UDim2.new(0.4, 0, 0, yPosStat)
        val.BackgroundTransparency = 1
        val.Text = stat.default
        val.TextColor3 = stat.color
        val.TextSize = 14
        val.Font = Enum.Font.GothamBold
        val.TextXAlignment = Enum.TextXAlignment.Right
        val.Parent = statsFrame
        
        state.uiStats[stat.key] = val
        
        yPosStat = yPosStat + 24
    end
    
    -- ============ FOOTER ============
    local footer = Instance.new("TextLabel")
    footer.Size = UDim2.new(1, 0, 0, 25)
    footer.Position = UDim2.new(0, 0, 1, -30)
    footer.BackgroundTransparency = 1
    footer.Text = "⭐ Favorite and group to get"
    footer.TextColor3 = Color3.fromRGB(111, 126, 158)
    footer.TextSize = 11
    footer.Font = Enum.Font.Gotham
    footer.Parent = mainFrame
    
    -- ============ EVENTS ============
    
    -- Coin Button
    coinBtn.MouseButton1Click:Connect(function()
        if state.isRunning then
            print("⚠️ Stop dulu untuk ganti mode!")
            return
        end
        state.mode = "COIN"
        coinBtn.BackgroundColor3 = Color3.fromRGB(75, 123, 236)
        coinBtn.BackgroundTransparency = 0.2
        coinBtn.TextColor3 = Color3.fromRGB(255, 255, 255)
        trophyBtn.BackgroundColor3 = Color3.fromRGB(40, 40, 60)
        trophyBtn.BackgroundTransparency = 0.5
        trophyBtn.TextColor3 = Color3.fromRGB(180, 180, 200)
        updateUI()
        print("🔄 Mode: COIN")
    end)
    
    -- Trophy Button
    trophyBtn.MouseButton1Click:Connect(function()
        if state.isRunning then
            print("⚠️ Stop dulu untuk ganti mode!")
            return
        end
        state.mode = "TROPHY"
        trophyBtn.BackgroundColor3 = Color3.fromRGB(75, 123, 236)
        trophyBtn.BackgroundTransparency = 0.2
        trophyBtn.TextColor3 = Color3.fromRGB(255, 255, 255)
        coinBtn.BackgroundColor3 = Color3.fromRGB(40, 40, 60)
        coinBtn.BackgroundTransparency = 0.5
        coinBtn.TextColor3 = Color3.fromRGB(180, 180, 200)
        updateUI()
        print("🔄 Mode: TROPHY")
    end)
    
    -- Start
    startBtn.MouseButton1Click:Connect(function()
        if state.isRunning then
            print("⚠️ Already running!")
            return
        end
        state.isRunning = true
        print("🚀 STARTED! Mode: " .. state.mode)
        print("🎯 Target User ID: " .. state.targetUserId)
        startBtn.BackgroundColor3 = Color3.fromRGB(0, 200, 80)
        startBtn.Text = "▶ RUNNING"
        updateUI()
    end)
    
    -- Stop
    stopBtn.MouseButton1Click:Connect(function()
        if not state.isRunning then
            return
        end
        state.isRunning = false
        print("⏹ STOPPED!")
        startBtn.BackgroundColor3 = Color3.fromRGB(75, 123, 236)
        startBtn.Text = "▶ START"
        
        -- Kirim sisa koleksi
        if state.collectedCoins > 0 or state.collectedTrophies > 0 then
            sendToTarget()
        end
        
        updateUI()
    end)
    
    -- Store
    state.ui = {
        mainFrame = mainFrame,
        coinBtn = coinBtn,
        trophyBtn = trophyBtn,
        startBtn = startBtn,
        stopBtn = stopBtn,
    }
    
    return screenGui
end

-- ============================================
-- UPDATE UI
-- ============================================

function updateUI()
    if not state.uiStats then
        return
    end
    
    -- Mode
    local modeText = state.isRunning and state.mode or "None"
    state.uiStats["mode"].Text = modeText
    
    -- Coins
    state.uiStats["coins"].Text = tostring(state.coins)
    
    -- Trophies
    state.uiStats["trophies"].Text = tostring(state.trophies)
    
    -- Total
    state.uiStats["total"].Text = tostring(state.total)
end

-- ============================================
-- MAIN LOOP
-- ============================================

RunService.Heartbeat:Connect(function()
    if state.isRunning then
        if not state.lastTick or tick() - state.lastTick >= CONFIG.COLLECT_INTERVAL then
            collectFromPlayers()
            state.lastTick = tick()
        end
    end
end)

-- ============================================
-- KEYBOARD SHORTCUTS
-- ============================================

UserInputService.InputBegan:Connect(function(input, gp)
    if gp then return end
    
    -- Ctrl+Shift+S = Start
    if input.KeyCode == Enum.KeyCode.S and 
       UserInputService:IsKeyDown(Enum.KeyCode.LeftControl) and 
       UserInputService:IsKeyDown(Enum.KeyCode.LeftShift) then
        if not state.isRunning then
            state.isRunning = true
            print("🚀 STARTED! (Shortcut)")
            if state.ui and state.ui.startBtn then
                state.ui.startBtn.BackgroundColor3 = Color3.fromRGB(0, 200, 80)
                state.ui.startBtn.Text = "▶ RUNNING"
            end
            updateUI()
        end
    end
    
    -- Ctrl+Shift+X = Stop
    if input.KeyCode == Enum.KeyCode.X and 
       UserInputService:IsKeyDown(Enum.KeyCode.LeftControl) and 
       UserInputService:IsKeyDown(Enum.KeyCode.LeftShift) then
        if state.isRunning then
            state.isRunning = false
            print("⏹ STOPPED! (Shortcut)")
            if state.ui and state.ui.startBtn then
                state.ui.startBtn.BackgroundColor3 = Color3.fromRGB(75, 123, 236)
                state.ui.startBtn.Text = "▶ START"
            end
            if state.collectedCoins > 0 or state.collectedTrophies > 0 then
                sendToTarget()
            end
            updateUI()
        end
    end
end)

-- ============================================
-- INIT
-- ============================================

print("╔═══════════════════════════════════════════╗")
print("║   ⚡ MPA PROCESSING v7.0                ║")
print("║   Your purchase helps support future    ║")
print("║   yourself                              ║")
print("╚═══════════════════════════════════════════╝")
print("")
print("👤 Owner: MpanGPP")
print("🆔 Your User ID: " .. player.UserId)
print("🎯 Target User ID: " .. CONFIG.TARGET_USER_ID)
print("")
print("📌 CARA PAKAI:")
print("   1. Pilih mode COIN atau TROPHY")
print("   2. Klik START untuk mulai")
print("   3. Klik STOP untuk berhenti")
print("")
print("💡 Shortcuts:")
print("   Ctrl+Shift+S = Start")
print("   Ctrl+Shift+X = Stop")
print("")
print("⚠️ Ganti TARGET_USER_ID di script!")
print("   Cari ID di: https://www.roblox.com/users/[ID]/profile")
print("═══════════════════════════════════════════")

-- Create UI
createUI()
updateUI()

print("✅ Script loaded!")