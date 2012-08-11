/*
 * opensn0w
 *
 * Ramdisk Utilities
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 **/

#include <unistd.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/sockio.h>
#include <sys/ioctl.h>
#include <sys/sysctl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <net/if.h>
#include <assert.h>
#include <CoreFoundation/CoreFoundation.h>
#include <AvailabilityMacros.h>
#define MAC_OS_X_VERSION_MIN_REQUIRED MAC_OS_X_VERSION_10_5
#include <IOKit/IOCFPlugIn.h>

#include "xpwn/plist.h"

#include "IOUSBDeviceControllerLib.h"

#include "hfs_mount.h"

char *execve_env[] = { NULL };
char *execve_params[] = { "/sbin/sshd", NULL };
int untether(char* platform, char* build);

/* start comex code */
#define kIOSomethingPluginID CFUUIDGetConstantUUIDWithBytes(NULL, \
0x9E, 0x72, 0x21, 0x7E, 0x8A, 0x60, 0x11, 0xDB, \
0xBF, 0x57, 0x00, 0x0D, 0x93, 0x6D, 0x06, 0xD2)
#define kIOWhatTheFuckID CFUUIDGetConstantUUIDWithBytes(NULL, \
0xEA, 0x33, 0xBA, 0x4F, 0x8A, 0x60, 0x11, 0xDB, \
0x84, 0xDB, 0x00, 0x0D, 0x93, 0x6D, 0x06, 0xD2)

void init_usb()
{
	IOUSBDeviceDescriptionRef desc =
	    IOUSBDeviceDescriptionCreateFromDefaults(kCFAllocatorDefault);
	IOUSBDeviceDescriptionSetSerialString(desc,
					      CFSTR("opensn0w jailbreak ramdisk" __DATE__ " " __TIME__));

	CFArrayRef usb_interfaces = IOUSBDeviceDescriptionCopyInterfaces(desc);
	int i;
	for (i = 0; i < CFArrayGetCount(usb_interfaces); i++) {
		CFArrayRef arr1 = CFArrayGetValueAtIndex(usb_interfaces, i);

		if (CFArrayContainsValue
		    (arr1, CFRangeMake(0, CFArrayGetCount(arr1)), CFSTR("PTP")))
		{
			printf("[*] Found PTP interface.\n");
			break;
		}
	}

	IOUSBDeviceControllerRef controller;
	while (IOUSBDeviceControllerCreate(kCFAllocatorDefault, &controller)) {
		printf("[!] Unable to get USB device controller.\n");
		sleep(3);
	}
	IOUSBDeviceControllerSetDescription(controller, desc);

	CFMutableDictionaryRef match =
	    IOServiceMatching("IOUSBDeviceInterface");
	CFMutableDictionaryRef dict =
	    CFDictionaryCreateMutable(NULL, 0, &kCFTypeDictionaryKeyCallBacks,
				      &kCFTypeDictionaryValueCallBacks);
	CFDictionarySetValue(dict, CFSTR("USBDeviceFunction"), CFSTR("PTP"));
	CFDictionarySetValue(match, CFSTR("IOPropertyMatch"), dict);
	io_service_t service;
	while (1) {
		service =
		    IOServiceGetMatchingService(kIOMasterPortDefault, match);
		if (!service) {
			printf("[!] Didn't find PTP controller, trying again.\n");
			sleep(1);
		} else {
			break;
		}
	}
	IOCFPlugInInterface **iface;
	SInt32 score;
	printf("123\n");
	assert(!IOCreatePlugInInterfaceForService(service,
						  kIOSomethingPluginID,
						  kIOCFPlugInInterfaceID,
						  &iface, &score));
	void *thing;

	assert(!((*iface)->QueryInterface) (iface,
					    CFUUIDGetUUIDBytes
					    (kIOWhatTheFuckID), &thing));

	IOReturn(**table) (void *,...) = *((void **)thing);

	//open IOUSBDeviceInterfaceInterface
	(!table[0x10 / 4] (thing, 0));
	//set IOUSBDeviceInterfaceInterface class
	(!table[0x2c / 4] (thing, 0xff, 0));
	//set IOUSBDeviceInterfaceInterface sub-class
	(!table[0x30 / 4] (thing, 0x50, 0));
	//set IOUSBDeviceInterfaceInterface protocol
	(!table[0x34 / 4] (thing, 0x43, 0));
	//commit IOUSBDeviceInterfaceInterface configuration
	(!table[0x44 / 4] (thing, 0));
	IODestroyPlugInInterface(iface);
	//assert(!table[0x14/4](thing, 0));
}

void init_tcp()
{
	// from launchd
	struct ifaliasreq ifra;
	struct ifreq ifr;
	int s;

	memset(&ifr, 0, sizeof(ifr));
	strcpy(ifr.ifr_name, "lo0");

	if ((s = socket(AF_INET, SOCK_DGRAM, 0)) == -1)
		return;

	if (ioctl(s, SIOCGIFFLAGS, &ifr) != -1) {
		ifr.ifr_flags |= IFF_UP;
		assert(ioctl(s, SIOCSIFFLAGS, &ifr) != -1);
	}

	memset(&ifra, 0, sizeof(ifra));
	strcpy(ifra.ifra_name, "lo0");
	((struct sockaddr_in *)&ifra.ifra_addr)->sin_family = AF_INET;
	((struct sockaddr_in *)&ifra.ifra_addr)->sin_addr.s_addr =
	    htonl(INADDR_LOOPBACK);
	((struct sockaddr_in *)&ifra.ifra_addr)->sin_len =
	    sizeof(struct sockaddr_in);
	((struct sockaddr_in *)&ifra.ifra_mask)->sin_family = AF_INET;
	((struct sockaddr_in *)&ifra.ifra_mask)->sin_addr.s_addr =
	    htonl(IN_CLASSA_NET);
	((struct sockaddr_in *)&ifra.ifra_mask)->sin_len =
	    sizeof(struct sockaddr_in);

	assert(ioctl(s, SIOCAIFADDR, &ifra) != -1);

	assert(close(s) == 0);

}

/* end comex code */

char *get_system_platform(void)
{
	size_t size;
	char *machine;

	/* get machine length */
	sysctlbyname("hw.machine", NULL, &size, NULL, 0);

	/* get string */
	machine = malloc(size);
	if (!machine) {
		return NULL;
	}

	sysctlbyname("hw.machine", machine, &size, NULL, 0);

	return machine;
}

static void advance_cursor(void) {
	static int pos = 0;
	char cursor[4] = {'/', '-', '\\', '|'};
	printf("%c\b", cursor[pos]);
	fflush(stdout);
	pos = (pos + 1) % 4;
}

int main(int argc, char *argv[], char *env[])
{
	struct stat status;
	int i;
	char *platform, *build;
	AbstractFile *plistFile;
	Dictionary* info;
	StringValue *ProductBuild;
	
	for (i = 0; i < 100; i++) {
		printf("\n");
	}
	printf("*** Welcome to opensn0w - Jailbreak Ramdisk. ***\n");

	/* from iPhone-dataprotection restored */
	CFMutableDictionaryRef matching;
	io_service_t service = 0;
	matching = IOServiceMatching("IOWatchDogTimer");
	if (matching == NULL) {
		printf
		    ("unable to create matching dictionary for class IOWatchDogTimer\n");
	}

	service = IOServiceGetMatchingService(kIOMasterPortDefault, matching);
	if (service == 0) {
		printf
		    ("unable to create matching dictionary for class IOWatchDogTimer\n");
	}
	uint32_t zero = 0;
	CFNumberRef n =
	    CFNumberCreate(kCFAllocatorDefault, kCFNumberIntType, &zero);
	IORegistryEntrySetCFProperties(service, n);
	IOObjectRelease(service);

	//init_tcp();
	//init_usb();
	printf("[*] Core device initialization complete.\n");
	/* end */

	printf("[*] Waiting for disk to mount...\n");

	while (stat("/dev/disk0s1", &status) != 0) {	/* lwvm base partition */
		advance_cursor();
		usleep(500);
	}
	sleep(1);

	/* at this point, check the disk */
	printf("[*] Waiting for rootfs partition...\n");
	for (i = 0; i < 10; i++) {
		if (!stat("/dev/disk0s1s1", &status)) {
			system("/sbin/fsck_hfs -fy /dev/disk0s1s1");
			system("/sbin/mount_hfs /dev/disk0s1s1 /mnt1");
			break;
		}
		if (!stat("/dev/disk0s1", &status)) {
			system("/sbin/fsck_hfs -fy /dev/disk0s1");
			system("/sbin/mount_hfs /dev/disk0s1 /mnt1");
			break;
		}
		sleep(5);
	}
	
	
	printf("[*] Waiting for data partition...\n");
	for (i = 0; i < 10; i++) {
		if (!stat("/dev/disk0s2s1", &status)) {
			system("/sbin/fsck_hfs -fy /dev/disk0s2s1");
			system("/sbin/mount_hfs /dev/disk0s2s1 /mnt1/private/var");
			break;
		}
		if (!stat("/dev/disk0s1s2", &status)) {
			system("/sbin/fsck_hfs -fy /dev/disk0s1s2");
			system("/sbin/mount_hfs /dev/disk0s1s2 /mnt1/private/var");
			break;
		}
		sleep(5);
	}

	sleep(2);

	/* mount /dev, we're going to chroot into it. */
	printf("[*] Filesystem mounted to /mnt1.\n");

	printf("[*] Making RAM disk rw...\n");
	system("mount -uw /");

	printf("[*] Creating symbolic links...\n");
	system("rm -rf /mnt2");
	system("ln -sn /mnt1/private/var /mnt2");
	
	/* get name */
	platform = get_system_platform();

	printf("[*] Current device is %s.\n", platform);

	/* i need to make a usbmuxd daemon HERE */

	char* plist = "/mnt1/System/Library/CoreServices/SystemVersion.plist";
	if ((plistFile =
	     createAbstractFileFromFile(fopen(plist, "rb"))) != NULL) {
		plist = (char *)malloc(plistFile->getLength(plistFile));
		plistFile->read(plistFile, plist,
						plistFile->getLength(plistFile));
		plistFile->close(plistFile);
		info = createRoot(plist);
	} 
	
	ProductBuild = (StringValue *) getValueByKey(info, "ProductBuildVersion");
	if (ProductBuild != NULL) {
		printf("Target build is %s\n", ProductBuild->value);
		build = ProductBuild->value;
	}

	printf("[*] Jailbreaking filesystem...\n");
	system("sed -i old -e s/rw.*/rw/ -e s/ro/rw/ /mnt1/etc/fstab");

	printf("[!] Please reboot your device now. UNIMPLEMENTED.\n");
	while(1);

	return 0;
}
