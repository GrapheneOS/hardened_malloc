package grapheneos.hmalloc;

import com.android.tradefed.device.DeviceNotAvailableException;
import com.android.tradefed.testtype.DeviceJUnit4ClassRunner;
import com.android.tradefed.testtype.junit4.BaseHostJUnit4Test;

import org.junit.Test;
import org.junit.runner.RunWith;

import java.io.IOException;
import java.util.ArrayList;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.fail;

@RunWith(DeviceJUnit4ClassRunner.class)
public class MemtagTest extends BaseHostJUnit4Test {

    private static final String TEST_BINARY = "/data/local/tmp/memtag_test";

    enum Result {
        SUCCESS,
        // it's expected that the device is configured to use asymm MTE tag checking mode
        ASYNC_MTE_ERROR,
        SYNC_MTE_ERROR,
    }

    private static final int SEGV_EXIT_CODE = 139;

    private void runTest(String name, Result expectedResult) throws DeviceNotAvailableException {
        var args = new ArrayList<String>();
        args.add(TEST_BINARY);
        args.add(name);
        var device = getDevice();
        long deviceDate = device.getDeviceDate();
        String cmdLine = String.join(" ", args);
        var result = device.executeShellV2Command(cmdLine);

        int expectedExitCode = expectedResult == Result.SUCCESS ? 0 : SEGV_EXIT_CODE;

        assertEquals("process exit code", expectedExitCode, result.getExitCode().intValue());

        if (expectedResult == Result.SUCCESS) {
            return;
        }

        try {
            // wait a bit for debuggerd to capture the crash
            Thread.sleep(50);
        } catch (InterruptedException e) {
            throw new IllegalStateException(e);
        }

        try (var logcat = device.getLogcatSince(deviceDate)) {
            try (var s = logcat.createInputStream()) {
                String[] lines = new String(s.readAllBytes()).split("\n");
                boolean foundCmd = false;
                String cmd = "Cmdline: " + cmdLine;
                String expectedSignalCode = switch (expectedResult) {
                    case ASYNC_MTE_ERROR -> "SEGV_MTEAERR";
                    case SYNC_MTE_ERROR -> "SEGV_MTESERR";
                    default -> throw new IllegalStateException(expectedResult.name());
                };
                for (String line : lines) {
                    if (!foundCmd) {
                        if (line.contains(cmd)) {
                            foundCmd = true;
                        }
                        continue;
                    }

                    if (line.contains("signal 11 (SIGSEGV), code")) {
                        if (!line.contains(expectedSignalCode)) {
                            break;
                        } else {
                            return;
                        }
                    }

                    if (line.contains("backtrace")) {
                        break;
                    }
                }

                fail("missing " + expectedSignalCode + " crash in logcat");
            } catch (IOException e) {
                throw new IllegalStateException(e);
            }
        }
    }

    @Test
    public void tag_distinctness() throws DeviceNotAvailableException {
        runTest("tag_distinctness", Result.SUCCESS);
    }

    @Test
    public void read_after_free() throws DeviceNotAvailableException {
        runTest("read_after_free", Result.SYNC_MTE_ERROR);
    }

    @Test
    public void write_after_free() throws DeviceNotAvailableException {
        runTest("write_after_free", Result.ASYNC_MTE_ERROR);
    }

    @Test
    public void underflow_read() throws DeviceNotAvailableException {
        runTest("underflow_read", Result.SYNC_MTE_ERROR);
    }

    @Test
    public void underflow_write() throws DeviceNotAvailableException {
        runTest("underflow_write", Result.ASYNC_MTE_ERROR);
    }

    @Test
    public void overflow_read() throws DeviceNotAvailableException {
        runTest("overflow_read", Result.SYNC_MTE_ERROR);
    }

    @Test
    public void overflow_write() throws DeviceNotAvailableException {
        runTest("overflow_write", Result.ASYNC_MTE_ERROR);
    }

    @Test
    public void untagged_read() throws DeviceNotAvailableException {
        runTest("untagged_read", Result.SYNC_MTE_ERROR);
    }

    @Test
    public void untagged_write() throws DeviceNotAvailableException {
        runTest("untagged_write", Result.ASYNC_MTE_ERROR);
    }
}
