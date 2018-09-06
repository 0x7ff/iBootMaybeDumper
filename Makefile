.PHONY: all
all:
	xcrun -sdk iphoneos clang -arch arm64 -Weverything iBootMaybeDumper.c -o iBootMaybeDumper -O2
	codesign -s - --entitlements tfp0.plist iBootMaybeDumper

.PHONY: clean
clean:
	$(RM) iBootMaybeDumper
