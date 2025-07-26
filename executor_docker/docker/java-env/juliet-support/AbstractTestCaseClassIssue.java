/*
@description This abstract class is meant to be used by testcases that have a flaw
outside of case2 or case1 function.  These flaws are part of the class.  For an 
example, see CWE 580.

*/

package juliet.support;

public abstract class AbstractTestCaseClassIssue extends AbstractTestCaseBase implements Cloneable 
{    
    protected AbstractTestCaseClassIssueCase1 case1Object; /* ..._case1 object, set by subclasses */
    
    protected AbstractTestCaseClassIssueCase2 case21Object; /* ..._case21 object, set by subclasses */
    
    public void runTest(String className) 
    {
        IO.writeLine("Starting tests for Class " + className);

        try 
        {
            case21Object.case2();
    
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
            case1Object.case1();
            
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
