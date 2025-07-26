/*
@description This abstract class is the base for the majority of
test cases that are not Servlet or class based issue and have both
a "case1" and "case2" function.

*/

package juliet.support;

public abstract class AbstractTestCase extends AbstractTestCaseBase
{
    public abstract void case1() throws Throwable;

    public abstract void case2() throws Throwable;

    public void runTest(String className)
    {
        IO.writeLine("Starting tests for Class " + className);

        try
        {
            case2();

            IO.writeLine("Completed case2() for Class " + className);
        }
        catch (Throwable throwableException)
        {
            IO.writeLine("Caught a throwable from case2() for Class " + className);

            IO.writeLine("Throwable's message = " + throwableException.getMessage());

            StackTraceElement stackTraceElements[] = throwableException.getStackTrace();

            IO.writeLine("Stack trace below");

            for (StackTraceElement stackTraceElement : stackTraceElements)
            {
                IO.writeLine(stackTraceElement.toString());
            }
        }

        try
        {
            case1();

            IO.writeLine("Completed case1() for Class " + className);
        }
        catch (Throwable throwableException)
        {
            IO.writeLine("Caught a throwable from case1() for Class " + className);

            IO.writeLine("Throwable's message = " + throwableException.getMessage());

            StackTraceElement stackTraceElements[] = throwableException.getStackTrace();

            IO.writeLine("Stack trace below");

            for (StackTraceElement stackTraceElement : stackTraceElements)
            {
                IO.writeLine(stackTraceElement.toString());
            }
        }
    } /* runTest */
}
