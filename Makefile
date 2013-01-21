DEBIAN_DIST=experimental
HSN2_COMPONENT=thug

PKG=hsn2-$(HSN2_COMPONENT)_$(HSN2_VER)-$(BUILD_NUMBER)_all
package: clean
	mkdir -p $(PKG)/opt/hsn2/thug
	mkdir -p $(PKG)/etc/init.d
	mkdir -p $(PKG)/DEBIAN
	cp install_thug.sh $(PKG)/opt/hsn2/thug/
	cp *.py $(PKG)/opt/hsn2/thug/
	cp debian/initd $(PKG)/etc/init.d/hsn2-thug
	cp debian/postrm $(PKG)/DEBIAN
	chmod 0775 $(PKG)/DEBIAN/postrm
	cp debian/control $(PKG)/DEBIAN
	sed -i "s/{VER}/${HSN2_VER}-${BUILD_NUMBER}/" $(PKG)/DEBIAN/control
	sed -i "s/{DEBIAN_DIST}/${DEBIAN_DIST}/" $(PKG)/DEBIAN/control
	fakeroot dpkg -b $(PKG)
	
clean:
	rm -rf $(PKG)