-- ============================================
-- VORTEX AI - FISH IT 10x CATCH + AUTO INVENTORY
-- Dengan Fitur Minimize / Maximize Menu
-- TELEGRAM : @realvortexdigital
-- ============================================

local player = game.Players.LocalPlayer
local character = player.Character or player.CharacterAdded:Wait()
local root = character:WaitForChild("HumanoidRootPart")

-- ========== VARIABEL TOGGLE ==========
local autoCatchEnabled = false
local autoInventoryEnabled = false
local targetOnly = false
local isMinimized = false

-- ========== BUAT GUI ==========
local gui = Instance.new("ScreenGui")
gui.Name = "VortexFishGUI"
gui.Parent = player:WaitForChild("PlayerGui")
if not gui.Parent then gui.Parent = game:GetService("CoreGui") end

-- ========== FRAME UTAMA ==========
local frame = Instance.new("Frame")
frame.Size = UDim2.new(0, 280, 0, 220)
frame.Position = UDim2.new(0.5, -140, 0.5, -110)
frame.BackgroundColor3 = Color3.fromRGB(10, 10, 20)
frame.BackgroundTransparency = 0.05
frame.BorderSizePixel = 2
frame.BorderColor3 = Color3.fromRGB(0, 200, 255)
frame.Active = true
frame.Draggable = true
frame.Parent = gui

-- ========== TITLE BAR (dengan tombol minimize) ==========
local titleBar = Instance.new("Frame")
titleBar.Size = UDim2.new(1, 0, 0, 40)
titleBar.BackgroundColor3 = Color3.fromRGB(30, 30, 50)
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

-- ========== TOMBOL MINIMIZE / MAXIMIZE ==========
local minBtn = Instance.new("TextButton")
minBtn.Size = UDim2.new(0, 30, 0, 30)
minBtn.Position = UDim2.new(0.9, 0, 0.05, 0)
minBtn.BackgroundColor3 = Color3.fromRGB(60, 60, 80)
minBtn.BackgroundTransparency = 0.2
minBtn.Text = "−"
minBtn.TextColor3 = Color3.fromRGB(255, 255, 255)
minBtn.TextScaled = true
minBtn.Font = Enum.Font.GothamBold
minBtn.BorderSizePixel = 1
minBtn.BorderColor3 = Color3.fromRGB(100, 100, 150)
minBtn.Parent = titleBar

-- ========== SCROLL (KONTEN UTAMA) ==========
local scroll = Instance.new("ScrollingFrame")
scroll.Size = UDim2.new(1, -10, 1, -45)
scroll.Position = UDim2.new(0, 5, 0, 42)
scroll.BackgroundTransparency = 1
scroll.CanvasSize = UDim2.new(0, 0, 0, 200)
scroll.ScrollBarThickness = 6
scroll.Parent = frame

local layout = Instance.new("UIListLayout")
layout.Padding = UDim.new(0, 6)
layout.SortOrder = Enum.SortOrder.LayoutOrder
layout.Parent = scroll

-- ========== FUNGSI TOMBOL TOGGLE ==========
local function toggleButton(text, getter, setter)
    local btn = Instance.new("TextButton")
    btn.Size = UDim2.new(1, 0, 0, 38)
    btn.BackgroundColor3 = Color3.fromRGB(40, 40, 70)
    btn.BackgroundTransparency = 0.2
    btn.Text = text .. " [OFF]"
    btn.TextColor3 = Color3.fromRGB(255, 255, 255)
    btn.TextScaled = true
    btn.Font = Enum.Font.GothamBold
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

-- ========== CREDIT ==========
local credit = Instance.new("TextLabel")
credit.Size = UDim2.new(1, -10, 0, 20)
credit.Position = UDim2.new(0, 5, 0, 190)
credit.BackgroundTransparency = 1
credit.Text = "TELEGRAM : @realvortexdigital"
credit.TextColor3 = Color3.fromRGB(0, 200, 255)
credit.TextScaled = true
credit.Font = Enum.Font.GothamBold
credit.Parent = frame

-- ========== FUNGSI MINIMIZE / MAXIMIZE ==========
local function toggleMinimize()
    isMinimized = not isMinimized
    if isMinimized then
        frame.Size = UDim2.new(0, 280, 0, 45) -- Hanya title bar
        scroll.Visible = false
        credit.Visible = false
        minBtn.Text = "+"
        -- Sembunyikan semua tombol di scroll
        for _, child in ipairs(scroll:GetChildren()) do
            if child:IsA("TextButton") or child:IsA("Frame") then
                child.Visible = false
            end
        end
    else
        frame.Size = UDim2.new(0, 280, 0, 220)
        scroll.Visible = true
        credit.Visible = true
        minBtn.Text = "−"
        for _, child in ipairs(scroll:GetChildren()) do
            if child:IsA("TextButton") or child:IsA("Frame") then
                child.Visible = true
            end
        end
    end
end

minBtn.MouseButton1Click:Connect(toggleMinimize)

-- ========== DRAG (Title Bar) ==========
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

-- ========== DETEKSI REMOTE EVENT ==========
local castRemote = nil
local reelRemote = nil
local collectRemote = nil

for _, obj in ipairs(game:GetService("ReplicatedStorage"):GetDescendants()) do
    if obj:IsA("RemoteEvent") then
        local name = obj.Name:lower()
        if name:match("cast") or name:match("start") or name:match("fish") then
            castRemote = obj
        elseif name:match("reel") or name:match("stop") or name:match("collect") then
            reelRemote = obj
        elseif name:match("add") or name:match("inventory") or name:match("catch") then
            collectRemote = obj
        end
    end
end

-- ========== FITUR 1: 10x CATCH PER CAST ==========
toggleButton("10x Catch per Cast", function() return autoCatchEnabled end, function(v)
    autoCatchEnabled = v
    spawn(function()
        while autoCatchEnabled do
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
                print("[VORTEX] 10 fish caught and sent to inventory")
            end
            wait(0.2)
        end
    end)
end)

-- ========== FITUR 2: AUTO INVENTORY ==========
toggleButton("Auto Inventory (Collect All)", function() return autoInventoryEnabled end, function(v)
    autoInventoryEnabled = v
    spawn(function()
        while autoInventoryEnabled do
            for _, btn in ipairs(player.PlayerGui:GetDescendants()) do
                if btn:IsA("TextButton") or btn:IsA("ImageButton") then
                    local txt = btn.Text:lower()
                    if txt:match("collect") or txt:match("inventory") or txt:match("store") or txt:match("keep") then
                        btn:Click()
                        wait(0.05)
                    end
                end
            end
            for _, obj in ipairs(workspace:GetDescendants()) do
                if obj:IsA("ClickDetector") then
                    local p = obj.Parent
                    if p then
                        local name = p.Name:lower()
                        if name:match("inventory") or name:match("collect") or name:match("chest") or name:match("storage") then
                            obj:Click()
                            wait(0.05)
                        end
                    end
                end
            end
            wait(0.3)
        end
    end)
end)

-- ========== FITUR 3: TARGET FISH ==========
toggleButton("Target: Screate/Forgotten", function() return targetOnly end, function(v)
    targetOnly = v
    print("[VORTEX] Target mode: " .. (targetOnly and "Screate & Forgotten only" or "All fish"))
end)

workspace.ChildAdded:Connect(function(child)
    if not targetOnly then return end
    if child:IsA("Model") and child.Name:lower():match("fish") then
        local fishName = child:FindFirstChild("Name") or child:FindFirstChild("FishName")
        if fishName and fishName:IsA("StringValue") then
            local isTarget = false
            for _, target in ipairs({"Screate", "Forgotten"}) do
                if fishName.Value:lower():match(target:lower()) then
                    isTarget = true
                    break
                end
            end
            if not isTarget then
                child:Destroy()
                print("[VORTEX] Non-target fish removed")
            end
        end
    end
end)

-- ========== NOTIFIKASI ==========
print("=========================================")
print("     VORTEX FISH IT - 10x CATCH")
print("     Auto 10x Catch | Auto Inventory")
print("     Target: Screate / Forgotten")
print("     Minimize/ Maximize Menu (Tombol −/+)")
print("     TELEGRAM : @realvortexdigital")
print("=========================================")
print("")
print("CARA PAKAI:")
print("1. Klik '−' untuk minimize menu (jadi kecil)")
print("2. Klik '+' untuk maximize menu (kembali besar)")
print("3. Aktifkan fitur yang diinginkan")
