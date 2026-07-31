@echo off
echo ==============================================
echo   Iniciando SentinelScan - Security Dashboard
echo ==============================================
echo.

echo [1/2] Iniciando o Servidor de API (Backend) na porta 5001...
start "SentinelScan Backend" cmd /k "cd backend && npm run dev"

echo [2/2] Iniciando o Painel React (Frontend) na porta 5173...
start "SentinelScan Frontend" cmd /k "cd frontend && npm run dev"

echo.
echo ==============================================
echo   Pronto! Ambos os servidores foram abertos.
echo   - Backend: http://localhost:5001
echo   - Frontend: http://localhost:5173
echo ==============================================
pause
