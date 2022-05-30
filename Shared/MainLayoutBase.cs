using Microsoft.AspNetCore.Components;

namespace EncryptionHelper.Shared
{
    public class MainLayoutBase : LayoutComponentBase
    {
        protected bool DrawerOpen { get; set; } = false;

        protected void ToggleDrawer()
        {
            DrawerOpen = !DrawerOpen;
        }
    }
}
