!include "LogicLib.nsh"

!macro NSIS_HOOK_PREUNINSTALL
  DetailPrint "Removing LobbyLocker-managed firewall rules..."
  ExecWait '"$INSTDIR\lobbylocker.exe" --reset-firewall' $0
  ${If} $0 != 0
    MessageBox MB_OK|MB_ICONSTOP "LobbyLocker could not remove its firewall rules. Uninstall has stopped so you can retry Reset without losing the cleanup tool."
    Abort
  ${EndIf}
!macroend
