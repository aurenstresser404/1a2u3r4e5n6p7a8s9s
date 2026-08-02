-- ============================================
-- VORTEX FISH IT - AUTO 10x + NOTIF + ALL ITEMS
-- Support: Ghostfind | Element | Diamond | Forgotten | dll
-- TELEGRAM : @realvortexdigital
-- ============================================

local player = game.Players.LocalPlayer
local character = player.Character or player.CharacterAdded:Wait()
local root = character:WaitForChild("HumanoidRootPart")

-- ========== VARIABEL TOGGLE ==========
local autoFish = false
local autoSprint = false
local instantFastRed = false
local skipRarity = false
local autoNotify = false
local autoCollect = false
local isMinimized = false

-- ========== DAFTAR ITEM SUPPORT ==========
local supportedItems = {
    "Ghostfind", "Element", "Diamond", "Forgotten",
    "Screate", "Salmon", "Pet Collar", "Snakehead", "Zebra",
    "Ancient", "Jungle", "Mythic", "Legendary"
}

-- ========== BUAT GUI ==========
local gui = Instance.new("ScreenGui")
gui.Name = "VortexFishGUI"
gui.Parent = player:WaitForChild("PlayerGui")
if not gui.Parent then gui.Parent = game:GetService("CoreGui") end

-- ========== FRAME UTAMA ==========
local frame = Instance.new("Frame")
frame.Size = UDim2.new(0, 420, 0, 650)
frame.Position = UDim2.new(0.5, -210, 0.5, -325)
frame.BackgroundColor3 = Color3.fromRGB(20, 20, 35)
frame.BackgroundTransparency = 0.05
frame.BorderSizePixel = 2
frame.BorderColor3 = Color3.fromRGB(0, 200, 255)
frame.Active = true
frame.Draggable = true
frame.Parent = gui

-- ========== TITLE BAR ==========
local titleBar = Instance.new("Frame")
titleBar.Size = UDim2.new(1, 0, 0, 40)
titleBar.BackgroundColor3 = Color3.fromRGB(30, 30, 55)
titleBar.BackgroundTransparency = 0.3
titleBar.Parent = frame

local title = Instance.new("TextLabel")
title.Size = UDim2.new(0.7, 0, 1, 0)
title.Position = UDim2.new(0.05, 0, 0, 0)
title.BackgroundTransparency = 1
title.Text = "VORTEX FISH IT"
title.TextColor3 = Color3.fromRGB(0, 200, 255)
title.TextScaled = true
title.Font = Enum.Font.GothamBold
title.Parent = titleBar

-- Tombol Minimize
local minBtn = Instance.new("TextButton")
minBtn.Size = UDim2.new(0, 30, 0, 30)
minBtn.Position = UDim2.new(0.92, 0, 0.05, 0)
minBtn.BackgroundColor3 = Color3.fromRGB(60, 60, 80)
minBtn.BackgroundTransparency = 0.2
minBtn.Text = "−"
minBtn.TextColor3 = Color3.fromRGB(255, 255, 255)
minBtn.TextScaled = true
minBtn.Font = Enum.Font.GothamBold
minBtn.BorderSizePixel = 1
minBtn.BorderColor3 = Color3.fromRGB(100, 100, 150)
minBtn.Parent = titleBar

minBtn.MouseButton1Click:Connect(function()
    isMinimized = not isMinimized
    if isMinimized then
        frame.Size = UDim2.new(0, 420, 0, 45)
        scroll.Visible = false
        statusBar.Visible = false
        minBtn.Text = "+"
    else
        frame.Size = UDim2.new(0, 420, 0, 650)
        scroll.Visible = true
        statusBar.Visible = true
        minBtn.Text = "−"
    end
end)

-- ========== DRAG ==========
local drag, start, pos
titleBar.InputBegan:Connect(function(i)
    if i.UserInputType == Enum.UserInputType.MouseButton1 then
        drag = true
        start = i.Position
        pos = frame.Position
        i.Changed:Connect(function()
            if i.UserInputState == Enum.UserInputState.End then drag = false end
        end)
    end
end)
game:GetService("UserInputService").InputChanged:Connect(function(i)
    if i == frame and drag then
        local delta = i.Position - start
        frame.Position = UDim2.new(pos.X.Scale, pos.X.Offset + delta.X, pos.Y.Scale, pos.Y.Offset + delta.Y)
    end
end)

-- ========== SCROLL ==========
local scroll = Instance.new("ScrollingFrame")
scroll.Size = UDim2.new(1, -10, 1, -100)
scroll.Position = UDim2.new(0, 5, 0, 45)
scroll.BackgroundTransparency = 1
scroll.CanvasSize = UDim2.new(0, 0, 0, 750)
scroll.ScrollBarThickness = 6
scroll.Parent = frame

local layout = Instance.new("UIListLayout")
layout.Padding = UDim.new(0, 4)
layout.SortOrder = Enum.SortOrder.LayoutOrder
layout.Parent = scroll

-- ========== FUNGSI UI ==========
local function createSection(titleText)
    local section = Instance.new("Frame")
    section.Size = UDim2.new(1, 0, 0, 30)
    section.BackgroundColor3 = Color3.fromRGB(40, 40, 60)
    section.BackgroundTransparency = 0.4
    section.Parent = scroll

    local label = Instance.new("TextLabel")
    label.Size = UDim2.new(1, -10, 1, 0)
    label.Position = UDim2.new(0, 5, 0, 0)
    label.BackgroundTransparency = 1
    label.Text = titleText
    label.TextColor3 = Color3.fromRGB(255, 200, 100)
    label.TextScaled = true
    label.Font = Enum.Font.GothamBold
    label.TextXAlignment = Enum.TextXAlignment.Left
    label.Parent = section
    return section
end

local function createButton(text, callback)
    local btn = Instance.new("TextButton")
    btn.Size = UDim2.new(0.45, -5, 0, 32)
    btn.BackgroundColor3 = Color3.fromRGB(40, 40, 70)
    btn.BackgroundTransparency = 0.2
    btn.Text = text
    btn.TextColor3 = Color3.fromRGB(255, 255, 255)
    btn.TextScaled = true
    btn.Font = Enum.Font.Gotham
    btn.BorderSizePixel = 1
    btn.BorderColor3 = Color3.fromRGB(0, 100, 200)
    btn.Parent = scroll
    btn.MouseButton1Click:Connect(callback)
    return btn
end

local function createToggle(text, getter, setter)
    local btn = Instance.new("TextButton")
    btn.Size = UDim2.new(0.45, -5, 0, 32)
    btn.BackgroundColor3 = Color3.fromRGB(40, 40, 70)
    btn.BackgroundTransparency = 0.2
    btn.Text = text .. " [OFF]"
    btn.TextColor3 = Color3.fromRGB(255, 255, 255)
    btn.TextScaled = true
    btn.Font = Enum.Font.Gotham
    btn.BorderSizePixel = 1
    btn.BorderColor3 = Color3.fromRGB(0, 100, 200)
    btn.Parent = scroll
    btn.MouseButton1Click:Connect(function()
        local newState = not getter()
        setter(newState)
        btn.Text = text .. (newState and " [ON]" or " [OFF]")
        btn.BackgroundColor3 = newState and Color3.fromRGB(0, 150, 0) or Color3.fromRGB(40, 40, 70)
        print("[VORTEX] " .. text .. ": " .. (newState and "ON" or "OFF"))
    end)
    return btn
end

local function createDoubleRow(btn1, btn2)
    local row = Instance.new("Frame")
    row.Size = UDim2.new(1, 0, 0, 36)
    row.BackgroundTransparency = 1
    row.Parent = scroll

    btn1.Size = UDim2.new(0.45, -5, 0, 32)
    btn1.Position = UDim2.new(0, 0, 0.02, 0)
    btn1.Parent = row

    btn2.Size = UDim2.new(0.45, -5, 0, 32)
    btn2.Position = UDim2.new(0.52, 0, 0.02, 0)
    btn2.Parent = row
    return row
end

local function createProgress(text, current, max)
    local frame = Instance.new("Frame")
    frame.Size = UDim2.new(1, 0, 0, 28)
    frame.BackgroundColor3 = Color3.fromRGB(30, 30, 50)
    frame.BackgroundTransparency = 0.3
    frame.Parent = scroll

    local label = Instance.new("TextLabel")
    label.Size = UDim2.new(1, -10, 1, 0)
    label.Position = UDim2.new(0, 5, 0, 0)
    label.BackgroundTransparency = 1
    label.Text = text .. " (" .. current .. "/" .. max .. ")"
    label.TextColor3 = Color3.fromRGB(200, 200, 200)
    label.TextScaled = true
    label.Font = Enum.Font.Gotham
    label.TextXAlignment = Enum.TextXAlignment.Left
    label.Parent = frame

    local bar = Instance.new("Frame")
    bar.Size = UDim2.new((current / max) * 0.9, 0, 0.5, 0)
    bar.Position = UDim2.new(0.05, 0, 0.7, 0)
    bar.BackgroundColor3 = Color3.fromRGB(0, 200, 100)
    bar.BackgroundTransparency = 0.3
    bar.Parent = frame
    return frame
end

-- ========== DETEKSI REMOTE ==========
local castRemote = nil
local reelRemote = nil
local collectRemote = nil
local notifyRemote = nil

for _, obj in ipairs(game:GetService("ReplicatedStorage"):GetDescendants()) do
    if obj:IsA("RemoteEvent") then
        local name = obj.Name:lower()
        if name:match("cast") or name:match("start") or name:match("fish") then
            castRemote = obj
        elseif name:match("reel") or name:match("stop") or name:match("collect") then
            reelRemote = obj
        elseif name:match("add") or name:match("inventory") or name:match("catch") then
            collectRemote = obj
        elseif name:match("notif") or name:match("alert") or name:match("message") then
            notifyRemote = obj
        end
    end
end

-- ========== FITUR AUTO 10x FISHING ==========
local function do10xCatch()
    if castRemote and reelRemote then
        castRemote:FireServer("Cast")
        wait(0.05)
        for i = 1, 10 do
            reelRemote:FireServer("Reel")
            wait(0.02)
        end
        if collectRemote then
            for i = 1, 10 do
                collectRemote:FireServer("AddFish", "Screate")
                wait(0.01)
            end
        end
        return true
    end
    return false
end

-- ========== AUTO NOTIFIKASI ==========
local function sendNotification(title, text, duration)
    duration = duration or 3
    pcall(function()
        game:GetService("StarterGui"):SetCore("SendNotification", {
            Title = title or "VORTEX FISH IT",
            Text = text or "10x Catch Success!",
            Duration = duration
        })
    end)
    -- Kirim juga ke RemoteEvent jika ada
    if notifyRemote then
        notifyRemote:FireServer(title, text)
    end
    print("[VORTEX] NOTIF: " .. title .. " - " .. text)
end

-- ========== AUTO MASUK TAS (COLLECT ALL) ==========
local function autoCollectAll()
    -- Klik tombol Collect/Store di GUI
    for _, btn in ipairs(player.PlayerGui:GetDescendants()) do
        if btn:IsA("TextButton") or btn:IsA("ImageButton") then
            local txt = btn.Text:lower()
            if txt:match("collect") or txt:match("inventory") or txt:match("store") or txt:match("keep") or txt:match("bag") then
                btn:Click()
                wait(0.05)
            end
        end
    end
    -- Cari ClickDetector inventory
    for _, obj in ipairs(workspace:GetDescendants()) do
        if obj:IsA("ClickDetector") then
            local p = obj.Parent
            if p then
                local name = p.Name:lower()
                if name:match("inventory") or name:match("collect") or name:match("chest") or name:match("storage") or name:match("bag") then
                    obj:Click()
                    wait(0.05)
                end
            end
        end
    end
end

-- ========== DETEKSI IKAN MASUK ==========
workspace.ChildAdded:Connect(function(child)
    if child:IsA("Model") and child.Name:lower():match("fish") then
        local fishName = child:FindFirstChild("Name") or child:FindFirstChild("FishName")
        if fishName and fishName:IsA("StringValue") then
            local name = fishName.Value
            -- Cek apakah item support
            local isSupported = false
            for _, item in ipairs(supportedItems) do
                if name:lower():match(item:lower()) then
                    isSupported = true
                    break
                end
            end
            if isSupported and autoNotify then
                sendNotification("🎣 FISH CAUGHT!", name .. " (10x) masuk ke tas!", 3)
            end
            if autoCollect then
                autoCollectAll()
            end
        end
    end
end)

-- ========== BUILD UI ==========

-- === QUESTS ===
createSection("Quests")
createButton("View All", function() print("[VORTEX] View All Quests") end)

-- === MAIN ===
createSection("Main")
createProgress("Speak to Clara", 1, 1)

-- === SUPPORT FEATURES ===
createSection("Support Features")
createProgress("Catch 20 Salmon", 20, 20)
createProgress("Catch 5 Pet Collars", 0, 5)

-- === FAVORITE ===
createSection("Favorite")
createButton("Stable Result Good/Perfection", function() print("[VORTEX] Stable Result") end)

-- === TELEPORT & SKIP ===
local teleportBtn = createButton("Teleport", function() print("[VORTEX] Teleport") end)
local skipBtn = createButton("Skip Rarity", function() 
    skipRarity = not skipRarity
    skipBtn.Text = "Skip Rarity" .. (skipRarity and " [ON]" or " [OFF]")
    print("[VORTEX] Skip Rarity: " .. (skipRarity and "ON" or "OFF"))
end)

-- === ELEMENT QUEST ===
createSection("?★ Element Quest")

-- === SHOP & TRADE ===
local shopBtn = createButton("Shop", function() print("[VORTEX] Shop") end)
local tradeBtn = createButton("Trade", function() print("[VORTEX] Trade") end)

-- === LEGIT FISHING ===
createSection("Legit Fishing")

-- === AUTOMATION ===
createSection("Automation")
local instantFishBtn = createToggle("Instant Fishing", function() return autoFish end, function(v) 
    autoFish = v
    spawn(function()
        while autoFish do
            do10xCatch()
            wait(0.2)
        end
    end)
end)

local instantFastBtn = createToggle("Instant Fast Red [BETA]", function() return instantFastRed end, function(v) 
    instantFastRed = v 
end)

local sprintBtn = createToggle("Sprint", function() return autoSprint end, function(v) 
    autoSprint = v
    spawn(function()
        while autoSprint do
            if character and humanoid then
                humanoid.WalkSpeed = 50
            end
            wait(0.1)
        end
    end)
end)

-- === NOTIF & COLLECT ===
createSection("Notifications & Collect")
local notifBtn = createToggle("Auto Notif (10x)", function() return autoNotify end, function(v) 
    autoNotify = v 
    if v then sendNotification("VORTEX FISH IT", "Auto Notif ACTIVE!", 2) end
end)

local collectBtn = createToggle("Auto Masuk Tas", function() return autoCollect end, function(v) 
    autoCollect = v 
    if v then print("[VORTEX] Auto Collect ACTIVE") end
end)

-- === SUPPORTED ITEMS ===
createSection("Supported Items")
local itemList = Instance.new("TextLabel")
itemList.Size = UDim2.new(1, -10, 0, 40)
itemList.Position = UDim2.new(0, 5, 0, 0)
itemList.BackgroundTransparency = 1
itemList.Text = "Ghostfind | Element | Diamond | Forgotten | Screate | Salmon | Pet Collar | Snakehead | Zebra | Ancient | Jungle | Mythic | Legendary"
itemList.TextColor3 = Color3.fromRGB(150, 200, 255)
itemList.TextScaled = true
itemList.Font = Enum.Font.Gotham
itemList.TextWrapped = true
itemList.Parent = scroll

-- === MORE ===
createSection("More")
local autoBtn = createToggle("AUTO (All ON)", function() return autoFish end, function(v) 
    autoFish = v
    autoNotify = v
    autoCollect = v
    if v then
        sendNotification("VORTEX FISH IT", "AUTO MODE ACTIVE! 10x Catch + Notif + Collect", 3)
    end
end)

-- ========== STATUS BAR ==========
local statusBar = Instance.new("Frame")
statusBar.Size = UDim2.new(1, 0, 0, 50)
statusBar.Position = UDim2.new(0, 0, 1, -50)
statusBar.BackgroundColor3 = Color3.fromRGB(20, 20, 40)
statusBar.BackgroundTransparency = 0.1
statusBar.Parent = frame

local statusText = Instance.new("TextLabel")
statusText.Size = UDim2.new(1, -10, 1, 0)
statusText.Position = UDim2.new(0, 5, 0, 0)
statusText.BackgroundTransparency = 1
statusText.Text = "🎣 10x Catch | 📦 Auto Bag | 🔔 Notif ON | Support: Ghostfind, Element, Diamond, Forgotten"
statusText.TextColor3 = Color3.fromRGB(200, 200, 200)
statusText.TextScaled = true
statusText.Font = Enum.Font.Gotham
statusText.TextXAlignment = Enum.TextXAlignment.Left
statusText.Parent = statusBar

-- ========== CREDIT ==========
local credit = Instance.new("TextLabel")
credit.Size = UDim2.new(0.6, 0, 0, 18)
credit.Position = UDim2.new(0.2, 0, 1, -20)
credit.BackgroundTransparency = 1
credit.Text = "TELEGRAM : @realvortexdigital"
credit.TextColor3 = Color3.fromRGB(0, 200, 255)
credit.TextScaled = true
credit.Font = Enum.Font.GothamBold
credit.Parent = frame

-- ========== NOTIFIKASI AWAL ==========
sendNotification("VORTEX FISH IT", "Loaded! Support: Ghostfind, Element, Diamond, Forgotten", 4)

print("=========================================")
print("     VORTEX FISH IT - AUTO 10x + NOTIF")
print("     Support: Ghostfind | Element | Diamond | Forgotten")
print("     TELEGRAM : @realvortexdigital")
print("=========================================")
