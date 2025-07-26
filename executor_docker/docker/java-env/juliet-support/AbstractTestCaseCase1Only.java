/*
@description This abstract class is the base for test cases that only have a "case1" function.

*/

package juliet.support;

public abstract class AbstractTestCaseCase1Only extends AbstractTestCaseBase {

    public abstract void case1() throws Throwable;
    
    public void runTest(String className) 
    {
        IO.writeLine("Starting tests for Class " + className);

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
