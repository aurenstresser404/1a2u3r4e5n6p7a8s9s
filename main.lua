-- ============================================
-- VORTEX FAST CLIMB TOWER - AUTO FAST CLIMB
-- Manjat tower cepat tanpa auto jump
-- Speed 500 saat di tower, normal 16 saat di tanah
-- TELEGRAM : @realvortexdigital
-- ============================================

local player = game.Players.LocalPlayer
local character = player.Character or player.CharacterAdded:Wait()
local humanoid = character:WaitForChild("Humanoid")
local root = character:WaitForChild("HumanoidRootPart")

-- ========== VARIABEL ==========
local fastClimbEnabled = false
local normalSpeed = 16
local climbSpeed = 500

-- ========== FUNGSI DETEKSI CLIMB ==========
local function isClimbing()
    if not root then return false end
    local raycastParams = RaycastParams.new()
    raycastParams.FilterDescendantsInstances = {character}
    raycastParams.FilterType = Enum.RaycastFilterType.Blacklist
    
    local origin = root.Position
    local direction = root.CFrame.LookVector * 5
    local rayResult = workspace:Raycast(origin, direction, raycastParams)
    
    if rayResult then
        local normal = rayResult.Normal
        local angle = math.deg(math.acos(normal:Dot(Vector3.new(0, 1, 0))))
        if angle > 70 and angle < 110 then
            return true
        end
    end
    return false
end

-- ========== FUNGSI AUTO FAST CLIMB ==========
local function autoFastClimb()
    if not fastClimbEnabled or not humanoid then return end
    
    if isClimbing() then
        -- Saat di tower → speed 500, tanpa jump
        humanoid.WalkSpeed = climbSpeed
        -- Tetap gunakan JumpPower tinggi tapi tidak auto jump
        humanoid.JumpPower = 250
    else
        -- Saat di tanah → normal 16
        humanoid.WalkSpeed = normalSpeed
        humanoid.JumpPower = 50
    end
end

-- ========== BUAT GUI ==========
local gui = Instance.new("ScreenGui")
gui.Name = "VortexFastClimb"
gui.Parent = player:WaitForChild("PlayerGui")
if not gui.Parent then gui.Parent = game:GetService("CoreGui") end

local frame = Instance.new("Frame")
frame.Size = UDim2.new(0, 250, 0, 120)
frame.Position = UDim2.new(0.5, -125, 0.5, -60)
frame.BackgroundColor3 = Color3.fromRGB(10, 10, 25)
frame.BackgroundTransparency = 0.05
frame.BorderSizePixel = 2
frame.BorderColor3 = Color3.fromRGB(0, 200, 255)
frame.Active = true
frame.Draggable = true
frame.Parent = gui

-- Title
local title = Instance.new("TextLabel")
title.Size = UDim2.new(1, 0, 0, 35)
title.BackgroundColor3 = Color3.fromRGB(25, 25, 50)
title.BackgroundTransparency = 0.3
title.Text = "VORTEX FAST CLIMB"
title.TextColor3 = Color3.fromRGB(0, 200, 255)
title.TextScaled = true
title.Font = Enum.Font.GothamBold
title.Parent = frame

-- Tombol Toggle
local fastClimbBtn = Instance.new("TextButton")
fastClimbBtn.Size = UDim2.new(0.8, 0, 0, 40)
fastClimbBtn.Position = UDim2.new(0.1, 0, 0.4, 0)
fastClimbBtn.BackgroundColor3 = Color3.fromRGB(40, 40, 70)
fastClimbBtn.BackgroundTransparency = 0.2
fastClimbBtn.Text = "Fast Climb [OFF]"
fastClimbBtn.TextColor3 = Color3.fromRGB(255, 255, 255)
fastClimbBtn.TextScaled = true
fastClimbBtn.Font = Enum.Font.GothamBold
fastClimbBtn.BorderSizePixel = 1
fastClimbBtn.BorderColor3 = Color3.fromRGB(0, 100, 200)
fastClimbBtn.Parent = frame

fastClimbBtn.MouseButton1Click:Connect(function()
    fastClimbEnabled = not fastClimbEnabled
    fastClimbBtn.Text = fastClimbEnabled and "Fast Climb [ON]" or "Fast Climb [OFF]"
    fastClimbBtn.BackgroundColor3 = fastClimbEnabled and Color3.fromRGB(0, 150, 0) or Color3.fromRGB(40, 40, 70)
    print("[VORTEX] Fast Climb: " .. (fastClimbEnabled and "ON" or "OFF"))
end)

-- ========== LOOP DETEKSI CLIMB (TANPA AUTO JUMP) ==========
game:GetService("RunService").Heartbeat:Connect(function()
    autoFastClimb()
end)

-- ========== CREDIT ==========
local credit = Instance.new("TextLabel")
credit.Size = UDim2.new(1, 0, 0, 18)
credit.Position = UDim2.new(0, 0, 0.8, 0)
credit.BackgroundTransparency = 1
credit.Text = "TELEGRAM : @realvortexdigital"
credit.TextColor3 = Color3.fromRGB(0, 200, 255)
credit.TextScaled = true
credit.Font = Enum.Font.GothamBold
credit.Parent = frame

-- ========== DRAG ==========
local drag, start, pos
frame.InputBegan:Connect(function(i)
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

print("=========================================")
print("     VORTEX FAST CLIMB TOWER")
print("     Auto fast climb tanpa auto jump")
print("     Speed 500 saat di tower")
print("     Speed 16 saat di tanah")
print("     TELEGRAM : @realvortexdigital")
print("=========================================")
print("")
print("CARA PAKAI:")
print("1. Klik 'Fast Climb [OFF]' untuk mengaktifkan")
print("2. Saat di tower → speed 500 (tanpa auto jump)")
print("3. Saat di tanah → speed normal 16")
