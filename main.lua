-- ===== SPEED WALK MODULE =====
local player = game.Players.LocalPlayer
local char = player.Character or player.CharacterAdded:Wait()
local humanoid = char:WaitForChild("Humanoid")
local speedEnabled = false
local speedValue = 80
local originalSpeed = humanoid.WalkSpeed
local speedConnection = nil

-- Update referensi karakter saat respawn
player.CharacterAdded:Connect(function(newChar)
    char = newChar
    humanoid = newChar:WaitForChild("Humanoid")
    originalSpeed = humanoid.WalkSpeed
    if speedEnabled then
        humanoid.WalkSpeed = speedValue
    end
end)

-- Fungsi toggle speed
local function toggleSpeed()
    speedEnabled = not speedEnabled
    if speedEnabled then
        if not speedConnection then
            speedConnection = game:GetService("RunService").Heartbeat:Connect(function()
                if humanoid and humanoid.Parent then
                    humanoid.WalkSpeed = speedValue
                end
            end)
        end
        humanoid.WalkSpeed = speedValue
    else
        if speedConnection then
            speedConnection:Disconnect()
            speedConnection = nil
        end
        if humanoid and humanoid.Parent then
            humanoid.WalkSpeed = originalSpeed
        end
    end
end

-- ===== TAMBAHAN ELEMEN GUI =====
-- Tombol Speed Toggle (di dalam frame yang sudah ada)
local speedBtn = Instance.new("TextButton", frame)
speedBtn.Size = UDim2.new(0, 180, 0, 30)
speedBtn.Position = UDim2.new(0, 10, 0, 60)
speedBtn.Text = "SPEED OFF"
speedBtn.BackgroundColor3 = Color3.fromRGB(255, 0, 0)
speedBtn.MouseButton1Click:Connect(function()
    toggleSpeed()
    speedBtn.Text = speedEnabled and "SPEED ON" or "SPEED OFF"
    speedBtn.BackgroundColor3 = speedEnabled and Color3.fromRGB(0, 255, 0) or Color3.fromRGB(255, 0, 0)
end)

-- Input Slider / TextBox untuk nilai speed
local speedInput = Instance.new("TextBox", frame)
speedInput.Size = UDim2.new(0, 180, 0, 25)
speedInput.Position = UDim2.new(0, 10, 0, 95)
speedInput.PlaceholderText = "Speed value (default 80)"
speedInput.Text = "80"
speedInput.BackgroundColor3 = Color3.fromRGB(40, 40, 40)
speedInput.TextColor3 = Color3.fromRGB(255, 255, 255)
speedInput.FocusLost:Connect(function(enterPressed)
    if enterPressed then
        local val = tonumber(speedInput.Text)
        if val and val > 0 then
            speedValue = val
            if speedEnabled and humanoid then
                humanoid.WalkSpeed = speedValue
            end
        else
            speedInput.Text = tostring(speedValue)
        end
    end
end)
