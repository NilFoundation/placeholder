for dir in $(ls /nix/store | grep gtk4); do
    find /nix/store/$dir -name "org.gtk.gtk4.Settings.FileChooser.gschema.xml"
done
