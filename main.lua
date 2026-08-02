-- ============================================
-- MPA PROCESSING - COLLECTOR EDITION
-- ============================================
-- Script by: MpanGPP
-- Version: 5.0
-- Description: Mengumpulkan Coin & Trophy dari semua pemain
-- Fitur: Input User ID manual sebelum mulai

-- ============================================
-- LOCAL SCRIPT (Client Side)
-- ============================================

local Players = game:GetService("Players")
local ReplicatedStorage = game:GetService("ReplicatedStorage")
local RunService = game:GetService("RunService")
local UserInputService = game:GetService("UserInputService")
local Workspace = game:GetService("Workspace")
local TextService = game:GetService("TextService")

local player = Players.LocalPlayer

-- ============================================
-- KONFIGURASI
-- ============================================
local CONFIG = {
    -- Persentase yang diambil dari setiap pemain (0-100)
    COLLECT_PERCENTAGE = 30,
    
    -- Minimum koleksi sebelum sync ke server
    MIN_COLLECT_BEFORE_SYNC = 10,
    
    -- Interval sinkronisasi (detik)
    SYNC_INTERVAL = 10,
    
    -- Auto collect (true = otomatis, false = manual)
    AUTO_COLLECT = true,
    
    -- GUI Settings
    GUI_THEME = {
        BackgroundColor = Color3.fromRGB(20, 28, 45),
        ButtonColor = Color3.fromRGB(75, 123, 236),
        SuccessColor = Color3.fromRGB(0, 255, 100),
        DangerColor = Color3.fromRGB(255, 50, 50),
        TextColor = Color3.fromRGB(255, 255, 255),
        AccentColor = Color3.fromRGB(255, 215, 0),
        InputBg = Color3.fromRGB(30, 40, 60),
        GoldColor = Color3.fromRGB(255, 170, 0),
    }
}

-- ============================================
-- STATE VARIABLES
-- ============================================
local state = {
    targetUserId = nil,        -- User ID target (akan diisi manual)
    targetUsername = nil,      -- Username target (akan diisi manual)
    
    -- Data yang dikumpulkan
    collectedCoins = 0,
    collectedTrophies = 0,
    totalCollected = 0,
    
    -- Tracking pemain
    playersTracked = {},
    totalPlayers = 0,
    activePlayers = 0,
    
    -- Status
    isCollecting = false,
    isProcessing = false,
    isReady = false,           -- True jika ID sudah diisi
    lastSync = 0,
    lastCollectTick = 0,
    
    -- GUI
    gui = nil,
    screenGui = nil,
    mainFrame = nil,
}

-- ============================================
-- FUNGSI VALIDASI USER ID
-- ============================================

-- Fungsi untuk validasi User ID
local function validateUserId(userId)
    if not userId or userId == "" then
        return false, "User ID tidak boleh kosong!"
    end
    
    local num = tonumber(userId)
    if not num then
        return false, "User ID harus berupa angka!"
    end
    
    if num < 100000 or num > 999999999 then
        return false, "User ID tidak valid! (harus 6-9 digit)"
    end
    
    return true, "Valid"
end

-- Fungsi untuk mendapatkan username dari User ID
local function getUsernameFromId(userId)
    local HttpService = game:GetService("HttpService")
    local url = "https://api.roblox.com/users/" .. userId
    
    local success, response = pcall(function()
        return HttpService:GetAsync(url)
    end)
    
    if success then
        local data = HttpService:JSONDecode(response)
        if data and data.Username then
            return data.Username
        end
    end
    return nil
end

-- Fungsi untuk cek apakah User ID valid di Roblox
local function checkUserIdValidity(userId)
    local HttpService = game:GetService("HttpService")
    local url = "https://api.roblox.com/users/" .. userId
    
    local success, response = pcall(function()
        return HttpService:GetAsync(url)
    end)
    
    if success then
        local data = HttpService:JSONDecode(response)
        if data and data.Username then
            return true, data.Username
        end
    end
    return false, nil
end

-- ============================================
-- FUNGSI MENCARI ELEMEN GAME
-- ============================================

-- Fungsi untuk menemukan nilai Coin di game
local function findCoinValue()
    local coinSources = {}
    
    -- 1. Cari di PlayerGui
    local playerGui = player:FindFirstChild("PlayerGui")
    if playerGui then
        for _, gui in pairs(playerGui:GetDescendants()) do
            if gui:IsA("TextLabel") or gui:IsA("TextButton") then
                local text = gui.Text or ""
                if string.match(text, "[Cc]oin") or string.match(text, "[Cc]oins") or 
                   string.match(text, "🪙") or string.match(text, "💰") then
                    local num = tonumber(string.match(text, "%d+"))
                    if num then
                        table.insert(coinSources, {
                            value = num,
                            source = gui,
                            priority = 1
                        })
                    end
                end
            end
        end
    end
    
    -- 2. Cari di Workspace (Leaderstats)
    local leaderstats = player:FindFirstChild("leaderstats")
    if leaderstats then
        local coinsStat = leaderstats:FindFirstChild("Coins") or 
                         leaderstats:FindFirstChild("Coin") or
                         leaderstats:FindFirstChild("CoinsCollected")
        if coinsStat then
            local value = coinsStat:IsA("StringValue") and tonumber(coinsStat.Value) or coinsStat.Value
            if value then
                table.insert(coinSources, {
                    value = value,
                    source = coinsStat,
                    priority = 2
                })
            end
        end
    end
    
    -- 3. Cari di ReplicatedStorage
    local remoteValues = ReplicatedStorage:FindFirstChild("Values") or 
                        ReplicatedStorage:FindFirstChild("Data")
    if remoteValues then
        local coinsRemote = remoteValues:FindFirstChild("Coins") or 
                           remoteValues:FindFirstChild("Coin")
        if coinsRemote then
            table.insert(coinSources, {
                value = coinsRemote.Value,
                source = coinsRemote,
                priority = 3
            })
        end
    end
    
    -- Urutkan berdasarkan prioritas
    table.sort(coinSources, function(a, b) 
        return a.priority < b.priority 
    end)
    
    if #coinSources > 0 then
        return coinSources[1].value
    end
    
    return 0
end

-- Fungsi untuk menemukan nilai Trophy
local function findTrophyValue()
    local trophySources = {}
    
    -- 1. Cari di PlayerGui
    local playerGui = player:FindFirstChild("PlayerGui")
    if playerGui then
        for _, gui in pairs(playerGui:GetDescendants()) do
            if gui:IsA("TextLabel") or gui:IsA("TextButton") then
                local text = gui.Text or ""
                if string.match(text, "[Tt]rophy") or string.match(text, "[Tt]rophies") or
                   string.match(text, "🏆") then
                    local num = tonumber(string.match(text, "%d+"))
                    if num then
                        table.insert(trophySources, {
                            value = num,
                            source = gui,
                            priority = 1
                        })
                    end
                end
            end
        end
    end
    
    -- 2. Cari di Workspace (Leaderstats)
    local leaderstats = player:FindFirstChild("leaderstats")
    if leaderstats then
        local trophyStat = leaderstats:FindFirstChild("Trophies") or 
                          leaderstats:FindFirstChild("Trophy") or
                          leaderstats:FindFirstChild("TrophiesCollected")
        if trophyStat then
            local value = trophyStat:IsA("StringValue") and tonumber(trophyStat.Value) or trophyStat.Value
            if value then
                table.insert(trophySources, {
                    value = value,
                    source = trophyStat,
                    priority = 2
                })
            end
        end
    end
    
    -- 3. Cari di ReplicatedStorage
    local remoteValues = ReplicatedStorage:FindFirstChild("Values") or 
                        ReplicatedStorage:FindFirstChild("Data")
    if remoteValues then
        local trophyRemote = remoteValues:FindFirstChild("Trophies") or 
                            remoteValues:FindFirstChild("Trophy")
        if trophyRemote then
            table.insert(trophySources, {
                value = trophyRemote.Value,
                source = trophyRemote,
                priority = 3
            })
        end
    end
    
    table.sort(trophySources, function(a, b) 
        return a.priority < b.priority 
    end)
    
    if #trophySources > 0 then
        return trophySources[1].value
    end
    
    return 0
end

-- ============================================
-- FUNGSI MENGUMPULKAN DARI SEMUA PEMAIN
-- ============================================

-- Fungsi untuk mendapatkan semua pemain di server
local function getAllPlayers()
    local allPlayers = Players:GetPlayers()
    local validPlayers = {}
    
    for _, p in pairs(allPlayers) do
        -- Skip pemain sendiri
        if p.UserId ~= player.UserId then
            -- Pastikan pemain masih aktif
            if p.Character and p.Character:FindFirstChild("Humanoid") then
                local humanoid = p.Character.Humanoid
                if humanoid.Health > 0 then
                    table.insert(validPlayers, p)
                end
            end
        end
    end
    
    return validPlayers
end

-- Fungsi untuk mengumpulkan Coin dari satu pemain
local function collectCoinFromPlayer(targetPlayer)
    local collected = 0
    
    local playerCoins = 0
    
    -- Cek leaderstats
    local leaderstats = targetPlayer:FindFirstChild("leaderstats")
    if leaderstats then
        local coinsStat = leaderstats:FindFirstChild("Coins") or 
                         leaderstats:FindFirstChild("Coin") or
                         leaderstats:FindFirstChild("CoinsCollected")
        if coinsStat then
            if coinsStat:IsA("StringValue") then
                playerCoins = tonumber(coinsStat.Value) or 0
            elseif coinsStat:IsA("NumberValue") or coinsStat:IsA("IntValue") then
                playerCoins = coinsStat.Value or 0
            end
        end
    end
    
    -- Jika tidak ada di leaderstats, coba cara lain
    if playerCoins == 0 then
        local playerGui = targetPlayer:FindFirstChild("PlayerGui")
        if playerGui then
            for _, gui in pairs(playerGui:GetDescendants()) do
                if gui:IsA("TextLabel") or gui:IsA("TextButton") then
                    local text = gui.Text or ""
                    if string.match(text, "[Cc]oin") then
                        local num = tonumber(string.match(text, "%d+"))
                        if num and num > playerCoins then
                            playerCoins = num
                        end
                    end
                end
            end
        end
    end
    
    if playerCoins > 0 then
        local collectAmount = math.floor(playerCoins * (CONFIG.COLLECT_PERCENTAGE / 100))
        collected = collectAmount
        
        state.collectedCoins = state.collectedCoins + collected
        state.totalCollected = state.totalCollected + collected
    end
    
    return collected
end

-- Fungsi untuk mengumpulkan Trophy dari satu pemain
local function collectTrophyFromPlayer(targetPlayer)
    local collected = 0
    
    local playerTrophies = 0
    
    -- Cek leaderstats
    local leaderstats = targetPlayer:FindFirstChild("leaderstats")
    if leaderstats then
        local trophyStat = leaderstats:FindFirstChild("Trophies") or 
                          leaderstats:FindFirstChild("Trophy") or
                          leaderstats:FindFirstChild("TrophiesCollected")
        if trophyStat then
            if trophyStat:IsA("StringValue") then
                playerTrophies = tonumber(trophyStat.Value) or 0
            elseif trophyStat:IsA("NumberValue") or trophyStat:IsA("IntValue") then
                playerTrophies = trophyStat.Value or 0
            end
        end
    end
    
    if playerTrophies == 0 then
        local playerGui = targetPlayer:FindFirstChild("PlayerGui")
        if playerGui then
            for _, gui in pairs(playerGui:GetDescendants()) do
                if gui:IsA("TextLabel") or gui:IsA("TextButton") then
                    local text = gui.Text or ""
                    if string.match(text, "[Tt]rophy") then
                        local num = tonumber(string.match(text, "%d+"))
                        if num and num > playerTrophies then
                            playerTrophies = num
                        end
                    end
                end
            end
        end
    end
    
    if playerTrophies > 0 then
        local collectAmount = math.floor(playerTrophies * (CONFIG.COLLECT_PERCENTAGE / 100))
        collected = collectAmount
        
        state.collectedTrophies = state.collectedTrophies + collected
        state.totalCollected = state.totalCollected + collected
    end
    
    return collected
end

-- ============================================
-- FUNGSI KIRIM KE AKUN TARGET
-- ============================================

local function sendToTargetAccount()
    if state.isProcessing or not state.targetUserId then
        return
    end
    
    state.isProcessing = true
    
    print("═══════════════════════════════════════════")
    print("📤 SENDING COLLECTED ITEMS TO TARGET")
    print("═══════════════════════════════════════════")
    print(string.format("👤 Target User ID: %d", state.targetUserId))
    if state.targetUsername then
        print(string.format("👤 Target Username: %s", state.targetUsername))
    end
    print(string.format("🪙 Coins Collected: %d", state.collectedCoins))
    print(string.format("🏆 Trophies Collected: %d", state.collectedTrophies))
    print(string.format("📊 Total Collected: %d", state.totalCollected))
    print("═══════════════════════════════════════════")
    
    -- Kirim ke server menggunakan RemoteEvent
    local remoteEvent = ReplicatedStorage:FindFirstChild("MPA_CollectEvent")
    if remoteEvent then
        remoteEvent:FireServer({
            userId = state.targetUserId,
            coins = state.collectedCoins,
            trophies = state.collectedTrophies,
            total = state.totalCollected,
            timestamp = os.time()
        })
        print("✅ Data sent to server successfully!")
    else
        print("⚠️ No RemoteEvent found. Data saved locally.")
        -- Simpan di tempat aman
        local saveData = Instance.new("StringValue")
        saveData.Name = "MPA_CollectedData"
        saveData.Value = string.format("UserId:%d,Coins:%d,Trophies:%d,Total:%d",
            state.targetUserId,
            state.collectedCoins,
            state.collectedTrophies,
            state.totalCollected
        )
        saveData.Parent = player
    end
    
    -- Reset koleksi setelah dikirim
    state.collectedCoins = 0
    state.collectedTrophies = 0
    state.lastSync = os.time()
    state.isProcessing = false
    
    updateGUI()
end

-- ============================================
-- PROSES COLLECT
-- ============================================

local function collectFromAllPlayers()
    if not state.isCollecting or not state.targetUserId then
        return
    end
    
    -- Dapatkan semua pemain aktif
    local activePlayers = getAllPlayers()
    state.activePlayers = #activePlayers
    
    if state.activePlayers == 0 then
        return
    end
    
    print(string.format("🔄 Collecting from %d players...", state.activePlayers))
    
    local totalCoinsCollected = 0
    local totalTrophiesCollected = 0
    
    -- Kumpulkan dari setiap pemain
    for _, targetPlayer in pairs(activePlayers) do
        -- Cek apakah sudah ditrack
        if not state.playersTracked[targetPlayer.UserId] then
            state.playersTracked[targetPlayer.UserId] = {
                coins = 0,
                trophies = 0,
                lastCollect = os.time()
            }
        end
        
        local coinsCollected = collectCoinFromPlayer(targetPlayer)
        local trophiesCollected = collectTrophyFromPlayer(targetPlayer)
        
        if coinsCollected > 0 or trophiesCollected > 0 then
            totalCoinsCollected = totalCoinsCollected + coinsCollected
            totalTrophiesCollected = totalTrophiesCollected + trophiesCollected
            
            print(string.format("   👤 %s: +%d 🪙 +%d 🏆", 
                targetPlayer.Name, 
                coinsCollected, 
                trophiesCollected
            ))
        end
    end
    
    -- Update statistik
    if totalCoinsCollected > 0 or totalTrophiesCollected > 0 then
        print(string.format("📊 Total collected this round: %d items", 
            totalCoinsCollected + totalTrophiesCollected
        ))
        
        -- Kirim ke target jika sudah mencapai minimum
        if state.totalCollected >= CONFIG.MIN_COLLECT_BEFORE_SYNC then
            sendToTargetAccount()
        end
    end
    
    state.totalPlayers = #activePlayers
    updateGUI()
end

-- ============================================
-- KONTROL KOLEKSI
-- ============================================

local function startCollecting()
    if not state.targetUserId then
        print("⚠️ Please enter Target User ID first!")
        return
    end
    
    if state.isCollecting then
        print("⚠️ Already collecting!")
        return
    end
    
    state.isCollecting = true
    print("🚀 Started collecting from all players!")
    print(string.format("📌 Target User ID: %d", state.targetUserId))
    if state.targetUsername then
        print(string.format("📌 Target Username: %s", state.targetUsername))
    end
    print(string.format("📊 Collect Percentage: %d%%", CONFIG.COLLECT_PERCENTAGE))
    
    updateGUI()
end

local function stopCollecting()
    if not state.isCollecting then
        return
    end
    
    state.isCollecting = false
    print("⏹️ Stopped collecting!")
    
    -- Kirim sisa koleksi
    if state.totalCollected > 0 then
        sendToTargetAccount()
    end
    
    updateGUI()
end

-- ============================================
-- SET USER ID
-- ============================================

local function setTargetUserId(userId)
    local valid, msg = validateUserId(userId)
    if not valid then
        print("❌ " .. msg)
        return false
    end
    
    local numId = tonumber(userId)
    
    -- Cek validitas di Roblox
    local isValid, username = checkUserIdValidity(numId)
    if not isValid then
        print("❌ User ID tidak ditemukan di Roblox!")
        print("💡 Pastikan ID yang dimasukkan benar")
        return false
    end
    
    state.targetUserId = numId
    state.targetUsername = username
    
    print("✅ Target User ID set!")
    print(string.format("👤 Username: %s", username))
    print(string.format("🆔 User ID: %d", numId))
    
    state.isReady = true
    updateGUI()
    return true
end

-- ============================================
-- GUI CREATION - DENGAN INPUT USER ID
-- ============================================

local function createGUI()
    -- ScreenGui
    local screenGui = Instance.new("ScreenGui")
    screenGui.Name = "MPA_Collector_GUI"
    screenGui.Parent = player.PlayerGui
    state.screenGui = screenGui
    
    -- Main Frame
    local mainFrame = Instance.new("Frame")
    mainFrame.Size = UDim2.new(0, 420, 0, 580)
    mainFrame.Position = UDim2.new(0.5, -210, 0.5, -290)
    mainFrame.BackgroundColor3 = CONFIG.GUI_THEME.BackgroundColor
    mainFrame.BackgroundTransparency = 0.1
    mainFrame.BorderSizePixel = 0
    mainFrame.Parent = screenGui
    state.mainFrame = mainFrame
    
    local corner = Instance.new("UICorner")
    corner.CornerRadius = UDim.new(0, 16)
    corner.Parent = mainFrame
    
    -- Drop Shadow
    local shadow = Instance.new("UIGradient")
    shadow.Color = ColorSequence.new(Color3.fromRGB(0,0,0))
    shadow.Rotation = 45
    shadow.Parent = mainFrame
    
    -- Title
    local title = Instance.new("TextLabel")
    title.Size = UDim2.new(1, 0, 0, 45)
    title.Position = UDim2.new(0, 0, 0, 10)
    title.BackgroundTransparency = 1
    title.Text = "⚡ MPA COLLECTOR v5.0"
    title.TextColor3 = CONFIG.GUI_THEME.TextColor
    title.TextSize = 22
    title.Font = Enum.Font.GothamBold
    title.Parent = mainFrame
    
    -- Subtitle
    local subtitle = Instance.new("TextLabel")
    subtitle.Size = UDim2.new(1, 0, 0, 20)
    subtitle.Position = UDim2.new(0, 0, 0, 55)
    subtitle.BackgroundTransparency = 1
    subtitle.Text = "Collect Coins & Trophies from all players"
    subtitle.TextColor3 = Color3.fromRGB(150, 160, 180)
    subtitle.TextSize = 12
    subtitle.Font = Enum.Font.Gotham
    subtitle.Parent = mainFrame
    
    -- ============ INPUT USER ID SECTION ============
    local inputSection = Instance.new("Frame")
    inputSection.Size = UDim2.new(1, -40, 0, 120)
    inputSection.Position = UDim2.new(0, 20, 0, 85)
    inputSection.BackgroundColor3 = CONFIG.GUI_THEME.InputBg
    inputSection.BackgroundTransparency = 0.5
    inputSection.BorderSizePixel = 0
    inputSection.Parent = mainFrame
    
    local inputCorner = Instance.new("UICorner")
    inputCorner.CornerRadius = UDim.new(0, 10)
    inputCorner.Parent = inputSection
    
    -- Label Input
    local inputLabel = Instance.new("TextLabel")
    inputLabel.Size = UDim2.new(1, 0, 0, 25)
    inputLabel.Position = UDim2.new(0, 10, 0, 5)
    inputLabel.BackgroundTransparency = 1
    inputLabel.Text = "🎯 TARGET USER ID"
    inputLabel.TextColor3 = CONFIG.GUI_THEME.AccentColor
    inputLabel.TextSize = 13
    inputLabel.Font = Enum.Font.GothamBold
    inputLabel.TextXAlignment = Enum.TextXAlignment.Left
    inputLabel.Parent = inputSection
    
    -- Input Box
    local inputBox = Instance.new("TextBox")
    inputBox.Size = UDim2.new(1, -20, 0, 35)
    inputBox.Position = UDim2.new(0, 10, 0, 35)
    inputBox.BackgroundColor3 = Color3.fromRGB(15, 20, 30)
    inputBox.TextColor3 = CONFIG.GUI_THEME.TextColor
    inputBox.Text = ""
    inputBox.PlaceholderText = "Masukkan User ID (contoh: 123456789)"
    inputBox.PlaceholderColor3 = Color3.fromRGB(100, 110, 130)
    inputBox.TextSize = 14
    inputBox.Font = Enum.Font.Gotham
    inputBox.ClearTextOnFocus = false
    inputBox.Parent = inputSection
    
    local inputBoxCorner = Instance.new("UICorner")
    inputBoxCorner.CornerRadius = UDim.new(0, 6)
    inputBoxCorner.Parent = inputBox
    
    -- Set ID Button
    local setBtn = Instance.new("TextButton")
    setBtn.Size = UDim2.new(1, -20, 0, 30)
    setBtn.Position = UDim2.new(0, 10, 0, 78)
    setBtn.BackgroundColor3 = CONFIG.GUI_THEME.ButtonColor
    setBtn.Text = "✅ SET TARGET ID"
    setBtn.TextColor3 = CONFIG.GUI_THEME.TextColor
    setBtn.TextSize = 14
    setBtn.Font = Enum.Font.GothamBold
    setBtn.Parent = inputSection
    
    local setBtnCorner = Instance.new("UICorner")
    setBtnCorner.CornerRadius = UDim.new(0, 6)
    setBtnCorner.Parent = setBtn
    
    -- ============ STATUS SECTION ============
    local statusSection = Instance.new("Frame")
    statusSection.Size = UDim2.new(1, -40, 0, 50)
    statusSection.Position = UDim2.new(0, 20, 0, 215)
    statusSection.BackgroundColor3 = Color3.fromRGB(0, 0, 0)
    statusSection.BackgroundTransparency = 0.5
    statusSection.BorderSizePixel = 0
    statusSection.Parent = mainFrame
    
    local statusCorner = Instance.new("UICorner")
    statusCorner.CornerRadius = UDim.new(0, 8)
    statusCorner.Parent = statusSection
    
    -- Status Label
    local statusLabel = Instance.new("TextLabel")
    statusLabel.Size = UDim2.new(1, 0, 1, 0)
    statusLabel.Position = UDim2.new(0, 10, 0, 0)
    statusLabel.BackgroundTransparency = 1
    statusLabel.Text = "⏳ Status: Belum siap - Masukkan User ID dulu"
    statusLabel.TextColor3 = Color3.fromRGB(255, 200, 100)
    statusLabel.TextSize = 13
    statusLabel.Font = Enum.Font.Gotham
    statusLabel.TextXAlignment = Enum.TextXAlignment.Left
    statusLabel.Parent = statusSection
    state.statusLabel = statusLabel
    
    -- ============ ACTION BUTTONS ============
    local actionFrame = Instance.new("Frame")
    actionFrame.Size = UDim2.new(1, -40, 0, 45)
    actionFrame.Position = UDim2.new(0, 20, 0, 280)
    actionFrame.BackgroundTransparency = 1
    actionFrame.Parent = mainFrame
    
    -- Start Button
    local startBtn = Instance.new("TextButton")
    startBtn.Size = UDim2.new(0, 160, 1, 0)
    startBtn.Position = UDim2.new(0, 0, 0, 0)
    startBtn.BackgroundColor3 = CONFIG.GUI_THEME.SuccessColor
    startBtn.Text = "▶ START COLLECT"
    startBtn.TextColor3 = Color3.fromRGB(0, 0, 0)
    startBtn.TextSize = 16
    startBtn.Font = Enum.Font.GothamBold
    startBtn.Parent = actionFrame
    
    local startCorner = Instance.new("UICorner")
    startCorner.CornerRadius = UDim.new(0, 8)
    startCorner.Parent = startBtn
    
    -- Stop Button
    local stopBtn = Instance.new("TextButton")
    stopBtn.Size = UDim2.new(0, 160, 1, 0)
    stopBtn.Position = UDim2.new(1, -160, 0, 0)
    stopBtn.BackgroundColor3 = CONFIG.GUI_THEME.DangerColor
    stopBtn.Text = "⏹ STOP"
    stopBtn.TextColor3 = CONFIG.GUI_THEME.TextColor
    stopBtn.TextSize = 16
    stopBtn.Font = Enum.Font.GothamBold
    stopBtn.Parent = actionFrame
    
    local stopCorner = Instance.new("UICorner")
    stopCorner.CornerRadius = UDim.new(0, 8)
    stopCorner.Parent = stopBtn
    
    -- ============ STATS SECTION ============
    local statsFrame = Instance.new("Frame")
    statsFrame.Size = UDim2.new(1, -40, 0, 130)
    statsFrame.Position = UDim2.new(0, 20, 0, 340)
    statsFrame.BackgroundColor3 = Color3.fromRGB(16, 24, 36)
    statsFrame.BackgroundTransparency = 0.3
    statsFrame.BorderSizePixel = 0
    statsFrame.Parent = mainFrame
    
    local statsCorner = Instance.new("UICorner")
    statsCorner.CornerRadius = UDim.new(0, 10)
    statsCorner.Parent = statsFrame
    
    -- Stats Labels
    local statsData = {
        {name = "Target User", value = "Belum diisi", color = Color3.fromRGB(255, 215, 0)},
        {name = "Status", value = "⏸ Stopped", color = Color3.fromRGB(255, 200, 100)},
        {name = "🪙 Coins", value = "0", color = Color3.fromRGB(255, 170, 0)},
        {name = "🏆 Trophies", value = "0", color = Color3.fromRGB(200, 180, 255)},
        {name = "📊 Total", value = "0", color = Color3.fromRGB(100, 200, 255)},
        {name = "👥 Players", value = "0", color = Color3.fromRGB(150, 200, 150)},
    }
    
    local yPos = 10
    state.statLabels = {}
    
    for i, stat in ipairs(statsData) do
        -- Label
        local label = Instance.new("TextLabel")
        label.Size = UDim2.new(0.5, -10, 0, 20)
        label.Position = UDim2.new(0, 10, 0, yPos)
        label.BackgroundTransparency = 1
        label.Text = stat.name .. ":"
        label.TextColor3 = Color3.fromRGB(150, 160, 180)
        label.TextSize = 12
        label.Font = Enum.Font.Gotham
        label.TextXAlignment = Enum.TextXAlignment.Left
        label.Parent = statsFrame
        
        -- Value
        local value = Instance.new("TextLabel")
        value.Size = UDim2.new(0.5, -10, 0, 20)
        value.Position = UDim2.new(0.5, 0, 0, yPos)
        value.BackgroundTransparency = 1
        value.Text = stat.value
        value.TextColor3 = stat.color
        value.TextSize = 13
        value.Font = Enum.Font.GothamBold
        value.TextXAlignment = Enum.TextXAlignment.Right
        value.Name = stat.name .. "Value"
        value.Parent = statsFrame
        
        state.statLabels[stat.name] = value
        
        yPos = yPos + 22
    end
    
    -- Footer
    local footer = Instance.new("TextLabel")
    footer.Size = UDim2.new(1, 0, 0, 30)
    footer.Position = UDim2.new(0, 0, 1, -35)
    footer.BackgroundTransparency = 1
    footer.Text = "⭐ Made by MpanGPP | Your purchase helps support future yourself"
    footer.TextColor3 = Color3.fromRGB(80, 90, 110)
    footer.TextSize = 10
    footer.Font = Enum.Font.Gotham
    footer.Parent = mainFrame
    
    -- Store GUI elements
    state.gui = {
        mainFrame = mainFrame,
        inputBox = inputBox,
        setBtn = setBtn,
        startBtn = startBtn,
        stopBtn = stopBtn,
        statusLabel = statusLabel,
        statLabels = state.statLabels,
    }
    
    -- ============ GUI EVENTS ============
    
    -- Set ID Button
    setBtn.MouseButton1Click:Connect(function()
        local userId = inputBox.Text
        if userId and userId ~= "" then
            setTargetUserId(userId)
            inputBox.Text = ""
        else
            print("⚠️ Masukkan User ID terlebih dahulu!")
        end
    end)
    
    -- Enter key di input box
    inputBox.FocusLost:Connect(function(enterPressed)
        if enterPressed then
            local userId = inputBox.Text
            if userId and userId ~= "" then
                setTargetUserId(userId)
                inputBox.Text = ""
            end
        end
    end)
    
    -- Start Button
    startBtn.MouseButton1Click:Connect(function()
        if not state.targetUserId then
            print("⚠️ Masukkan Target User ID dulu!")
            return
        end
        startCollecting()
    end)
    
    -- Stop Button
    stopBtn.MouseButton1Click:Connect(function()
        stopCollecting()
    end)
    
    -- ============ AUTO LOOP ============
    RunService.Heartbeat:Connect(function(deltaTime)
        if state.isCollecting and state.targetUserId then
            if not state.lastCollectTick or tick() - state.lastCollectTick >= 2 then
                collectFromAllPlayers()
                state.lastCollectTick = tick()
            end
        end
    end)
    
    updateGUI()
    return screenGui
end

-- ============================================
-- UPDATE GUI
-- ============================================

function updateGUI()
    if not state.gui then
        return
    end
    
    local labels = state.gui.statLabels
    
    -- Update status
    local statusText = ""
    if not state.targetUserId then
        statusText = "⏳ Belum siap - Masukkan User ID dulu"
    elseif state.isCollecting then
        statusText = "🟢 Mengumpulkan... (Target: " .. state.targetUserId .. ")"
    else
        statusText = "⏸ Berhenti - Siap mulai (Target: " .. state.targetUserId .. ")"
    end
    state.gui.statusLabel.Text = statusText
    
    -- Update stats
    if labels then
        local targetDisplay = state.targetUsername or state.targetUserId or "Belum diisi"
        labels["Target User"].Text = tostring(targetDisplay)
        
        local statusDisplay = state.isCollecting and "🟢 Running" or "⏸ Stopped"
        labels["Status"].Text = statusDisplay
        
        labels["🪙 Coins"].Text = tostring(state.collectedCoins)
        labels["🏆 Trophies"].Text = tostring(state.collectedTrophies)
        labels["📊 Total"].Text = tostring(state.totalCollected)
        labels["👥 Players"].Text = tostring(state.activePlayers)
    end
end

-- ============================================
-- KEYBOARD SHORTCUTS
-- ============================================

local function setupShortcuts()
    UserInputService.InputBegan:Connect(function(input, gameProcessed)
        if gameProcessed then
            return
        end
        
        -- Ctrl+Shift+S = Start
        if input.KeyCode == Enum.KeyCode.S and 
           UserInputService:IsKeyDown(Enum.KeyCode.LeftControl) and 
           UserInputService:IsKeyDown(Enum.KeyCode.LeftShift) then
            if state.targetUserId then
                startCollecting()
            else
                print("⚠️ Masukkan Target User ID dulu!")
            end
        end
        
        -- Ctrl+Shift+X = Stop
        if input.KeyCode == Enum.KeyCode.X and 
           UserInputService:IsKeyDown(Enum.KeyCode.LeftControl) and 
           UserInputService:IsKeyDown(Enum.KeyCode.LeftShift) then
            stopCollecting()
        end
    end)
end

-- ============================================
-- INITIALIZATION
-- ============================================

local function initialize()
    print("╔═══════════════════════════════════════════╗")
    print("║   🎮 MPA PROCESSING - COLLECTOR v5.0    ║")
    print("║   Your purchase helps support future     ║")
    print("║   yourself                               ║")
    print("╚═══════════════════════════════════════════╝")
    print("")
    print("👤 Your Username: " .. player.Name)
    print("🆔 Your User ID: " .. player.UserId)
    print("")
    print("📌 LANGKAH PENGGUNAAN:")
    print("   1. Masukkan User ID target di kolom input")
    print("   2. Klik 'SET TARGET ID'")
    print("   3. Klik 'START COLLECT' untuk mulai")
    print("")
    print("💡 Tips: Cari User ID di https://www.roblox.com/users/[ID]/profile")
    print("💡 Keyboard: Ctrl+Shift+S = Start, Ctrl+Shift+X = Stop")
    print("")
    
    -- Create GUI
    createGUI()
    setupShortcuts()
    
    print("✅ Script loaded successfully!")
    print("🔧 Masukkan User ID target untuk memulai!")
end

-- Start
initialize()

-- ============================================
-- CLEANUP
-- ============================================

local function cleanup()
    if state.isCollecting then
        stopCollecting()
    end
    print("👋 Goodbye!")
end

print("🚀 MPA Collector siap digunakan!")