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
        SUCCESS(0, ""),
        // it's expected that the device is configured to use asymm MTE tag checking mode
        ASYNC_MTE_ERROR(139, "SEGV_CODE 8"),
        SYNC_MTE_ERROR(139, "SEGV_CODE 9"),
        ;

        public final int exitCode;
        public final String stderr;

        Result(int exitCode, String stderr) {
            this.exitCode = exitCode;
            this.stderr = stderr;
        }
    }

    private static final int SEGV_EXIT_CODE = 139;

    private void runTest(String name, Result expectedResult) throws DeviceNotAvailableException {
        var args = new ArrayList<String>();
        args.add(TEST_BINARY);
        args.add(name);
        String cmdLine = String.join(" ", args);

        var result = getDevice().executeShellV2Command(cmdLine);

        assertEquals("process exit code", expectedResult.exitCode, result.getExitCode().intValue());
        assertEquals("stderr", expectedResult.stderr, result.getStderr());
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
