package grapheneos.hmalloc;

import com.android.tradefed.device.DeviceNotAvailableException;
import com.android.tradefed.testtype.DeviceJUnit4ClassRunner;
import com.android.tradefed.testtype.junit4.BaseHostJUnit4Test;

import org.junit.Test;
import org.junit.runner.RunWith;

import java.util.ArrayList;

import static org.junit.Assert.assertEquals;

@RunWith(DeviceJUnit4ClassRunner.class)
public class MemtagTest extends BaseHostJUnit4Test {
    private static final String TEST_BINARY = "/data/local/tmp/memtag_test";

    private void runTest(String name) throws DeviceNotAvailableException {
        var args = new ArrayList<String>();
        args.add(TEST_BINARY);
        args.add(name);
        String cmdLine = String.join(" ", args);

        var result = getDevice().executeShellV2Command(cmdLine);

        assertEquals("stderr", "", result.getStderr());
        assertEquals("process exit code", 0, result.getExitCode().intValue());
    }

    @Test
    public void tag_distinctness() throws DeviceNotAvailableException {
        runTest("tag_distinctness");
    }

    @Test
    public void read_after_free() throws DeviceNotAvailableException {
        runTest("read_after_free");
    }

    @Test
    public void write_after_free() throws DeviceNotAvailableException {
        runTest("write_after_free");
    }

    @Test
    public void underflow_read() throws DeviceNotAvailableException {
        runTest("underflow_read");
    }

    @Test
    public void underflow_write() throws DeviceNotAvailableException {
        runTest("underflow_write");
    }

    @Test
    public void overflow_read() throws DeviceNotAvailableException {
        runTest("overflow_read");
    }

    @Test
    public void overflow_write() throws DeviceNotAvailableException {
        runTest("overflow_write");
    }

    @Test
    public void untagged_read() throws DeviceNotAvailableException {
        runTest("untagged_read");
    }

    @Test
    public void untagged_write() throws DeviceNotAvailableException {
        runTest("untagged_write");
    }

    @Test
    public void madvise_dontneed() throws DeviceNotAvailableException {
        runTest("madvise_dontneed");
    }
}
