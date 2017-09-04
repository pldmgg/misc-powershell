using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Documents;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Navigation;
using System.Windows.Shapes;

namespace ParseCallMetrics
{
    /// <summary>
    /// Interaction logic for MainWindow.xaml
    /// </summary>
    public partial class MainWindow : Window
    {
        public MainWindow()
        {
            InitializeComponent();

            // Set Default Values for Form Controls When it is Initially Launched
            xamlCallTypeComboBox.Text = "Select Call Type";
            xamlDayOfWeekComboBox.Text = "Select Day Of The Week";

            // Allow Drag and Drop for xamlListBox
            // See additional xamlListBox functionality under xamlListBox_DragEnter 
            // and xamlListBox_Drop public methods below (~ Line 67)
            xamlExcelSpreadSheetPathsListBox.AllowDrop = true;
            xamlExcelSpreadSheetPathsListBox.Drop += xamlExcelSpreadSheetPathsListBox_Drop;
            xamlExcelSpreadSheetPathsListBox.DragEnter += xamlExcelSpreadSheetPathsListBox_DragEnter;
            /*
            // The AllControlsTextBox1 is present but hidden for the sake of learning, testing, and 
            // documenting C# and LINQ behavior. To hide a Form Control, use something like the following:
            xamlAllControlsTextBox1.Visibility = System.Windows.Visibility.Hidden;
            xamlAllControlsComboBox1.Visibility = System.Windows.Visibility.Hidden;
            xamlAllControlsListBox1.Visibility = System.Windows.Visibility.Hidden;
            // To make sure it doesn't take up any real estate on the form, use something like:
            xamlAllControlsTextBox1.Visibility = System.Windows.Visibility.Collapsed;
            xamlAllControlsComboBox1.Visibility = System.Windows.Visibility.Collapsed;
            xamlAllControlsListBox1.Visibility = System.Windows.Visibility.Collapsed;
            */
        }

        class BackgroundWorkerObj
        {
            public BackgroundWorker worker;
            public static AutoResetEvent resetEvent;
            public int progressValue = 0;

            // Default constructor with some default object properties:
            public BackgroundWorkerObj()
            {
                worker = new BackgroundWorker();
                resetEvent = new AutoResetEvent(false);
                progressValue = 0;
            }

            // A constructor that takes three specific types of properties:
            public BackgroundWorkerObj(BackgroundWorker bgw, AutoResetEvent reset, int val)
            {
                worker = bgw;
                resetEvent = reset;
                progressValue = val;
            }
        }

        // IMPORTANT NOTE: INCREDIBLY IMPORTANT - Static properties of a class can be referenced by ALL threads!!!!!!
        // This is why the below FormControls Class exists. The GetAllFormControls method sets 
        //     FormControls.FormControlDictionary = GetCallMetricsParamsDictionary;
        // ...and FormControls.FormControlDictionary is used in the RunPowerShellFunction which is being run in a
        // separate thread as part of a BackgroundWorker job.
        class FormControls
        {
            public static Dictionary<string, string> FormControlDictionary;
        }

        public Dictionary<string, string> GetAllFormControls()
        {
            ////// BEGIN Getting Form Controls //////

            // This is where we want to use our existing PowerShell function Get-CallMetrics. To do so,
            // we need to load PowerShell's main assembly, System.Management.Automation
            //
            // If Visual Studio complains about System.Management.Automation not existing / needing
            // an assembly reference, either:
            //
            // 1) Use NuGet to get System.Management.Automation via Tools -> NuGet PackageManager -> 
            // Package Manager Console and then in the console: 
            //     Install -Package System.Management.Automation
            // OR
            // 2) Add the assembly reference by pointing to the System.Management.Automation.dll file path
            // 
            // In the below, we are starting the process powershell.exe and then from within PowerShell,
            // we are running "[PSObject].Assembly.Location" which will return the full file path to 
            // System.Management.Automation.dll. We then load the .dll file directly using 
            //    var PowerShellDLL = System.Reflection.Assembly.LoadFrom(PSdllFilePath)
            // 
            // We could, however, simply run the PowerShell function by using the more familiar shell syntax:
            //     powershell.exe -command ". C:\Scripts\powershell\Get-CallMetrics.ps1; Get-CallMetrics @params"
            // ...where the -command string is placed within quotes here: cmd.StandardInput.WriteLine("")

            //////////// BEGIN Pass Form Control Inputs to Get-CallMetrics Function ////////////

            //////// Get All Form Control Objects ////////
            //// EASIEST METHOD ////
            // Using System.Collections.Generic.IEnumerable and UIElementCollection.Panel.Children
            // BENEFIT: Concise, readable, efficient
            // DRAWBACK: This only goes 1 level deep, which isn't sufficient for more complex forms
            IEnumerable<TextBox> TextBoxCollection = xamlGrid.Children.OfType<TextBox>();
            IEnumerable<ComboBox> ComboBoxCollection = xamlGrid.Children.OfType<ComboBox>();
            IEnumerable<ListBox> ListBoxCollection = xamlGrid.Children.OfType<ListBox>();
            IEnumerable<CheckBox> CheckBoxCollection = xamlGrid.Children.OfType<CheckBox>();
            // Use LINQ to filter out controls we do not care about
            // More on LINQ here: https://msdn.microsoft.com/en-us/library/bb397927.aspx
            // The below gets a filtered collection of Control Objects
            var FilteredTextBoxCollection =
                TextBoxCollection.Where(item => item.Name != "xamlAllControlsTextBox1").ToList();
            var FilteredComboBoxCollection =
                ComboBoxCollection.Where(item => item.Name != "xamlAllControlsComboBox1").ToList();
            var FilteredListBoxCollection =
                ListBoxCollection.Where(item => item.Name != "xamlAllControlsListBox1").ToList();
            var FilteredCheckBoxCollection =
                CheckBoxCollection.Where(item => item.Name != "xamlAllControlsCheckBox1").ToList();
            // The below gets a filtered collection of strings that represent the Name of each Control Object
            // var FilteredTextBoxStringCollection =
            //     TextBoxCollection.Where(item => item.Name != "xamlAllControlsTextBox1").Select(item => item.Name).ToList();
            // var FilteredComboBoxStringCollection =
            //     ComboBoxCollection.Where(item => item.Name != "xamlAllControlsComboBox1").Select(item => item.Name).ToList();
            // var FilteredListBoxStringCollection =
            //     ListBoxCollection.Where(item => item.Name != "xamlAllControlsListBox1").Select(item => item.Name).ToList();
            // Temporary Testing:
            // string FilteredTextBoxCollection = string.Join(",", FilteredTextBoxCollectionPrep);
            // xamlAllControlsTextBox2.Text = FilteredTextBoxCollection;

            //// ALTERNATE METHOD ////
            // Using the FindVisualChildren Method
            // BENEFIT: Gets ALL Controls No Matter How Deep
            // DRAWBACK: Need to write the FindVisualChildren Method (see above method)
            /*
            // First, create an empty System.Collections.Generic.List
            List<string> FormControls = new List<string>();
            // Then, create a foreach loop for each type of Form Control. Below demonstrates getting TextBox Controls.
            foreach (TextBox tb in FindVisualChildren<TextBox>(xamlGrid))
            {
                if (tb.Name != "xamlAllControlsTexBox1" && tb.Name != "xamlToPhoneExtTextBox")
                {
                    FormControls.Add(tb.Name);
                }
            }
            // Temporary Testing Without Using StringBulder
            string result = string.Join(",", FormControls);
            xamlAllControlsTexBox1.Text = result;

            // With using StringBuilder
            // StringBuilder builder = new StringBuilder();
            // foreach (string Control in FormControls) // Loop through all strings
            // {
            //     builder.Append(Control).Append(","); // Append string to StringBuilder
            // }
            // string result = builder.ToString(); // Get string from StringBuilder
            // xamlAllControlsTextBox1.Text = result
            */

            // Place all form control names and inputs into a Generic Dictionary (i.e. better version of hashtable)
            // Create an empty Dictionary
            Dictionary<string, string> GetCallMetricsParamsDictionary = new Dictionary<string, string>();
            // Loop through each Collection and get Name and Text properties
            string AllowedChars = @"^[a-zA-Z0-9+]";
            foreach (TextBox tb in FilteredTextBoxCollection)
            {
                if (Regex.IsMatch(tb.Text, AllowedChars))
                {
                    StringBuilder tbbuilder = new StringBuilder(tb.Name);
                    var ParamNamePrep1 = tbbuilder.Replace("xaml", "");
                    string ParamName = tbbuilder.Replace("TextBox", "").ToString();

                    string ParamValue = "\"" + tb.Text + "\"";

                    GetCallMetricsParamsDictionary.Add(ParamName, ParamValue);
                }
            }
            foreach (ComboBox cb in FilteredComboBoxCollection)
            {
                if (cb.SelectedItem != null)
                {
                    StringBuilder cbbuilder = new StringBuilder(cb.Name);
                    var ParamNamePrep1 = cbbuilder.Replace("xaml", "");
                    string ParamName = cbbuilder.Replace("ComboBox", "").ToString();

                    // The below:
                    //     string ParamValue = cb.SelectedItem.ToString();
                    // ...results in printing the following string (which is NOT what we want):
                    //     System.Windows.Controls.ComboBoxItem: Call Count
                    // Instead, we just want the string "Call Count" so we use the following:
                    string ParamValue = "\"" + (cb.SelectedItem as ComboBoxItem).Content.ToString() + "\"";

                    GetCallMetricsParamsDictionary.Add(ParamName, ParamValue);
                }
            }
            foreach (ListBox lb in FilteredListBoxCollection)
            {
                StringBuilder lbbuilder = new StringBuilder(lb.Name);
                var ParamNamePrep1 = lbbuilder.Replace("xaml", "");
                string ParamName = lbbuilder.Replace("ListBox", "").ToString();

                // Get all ListBox Items using LINQ
                // This LINQ solution came from: 
                // http://stackoverflow.com/questions/471595/casting-an-item-collection-from-a-listbox-to-a-generic-list
                List<string> ListBoxSpreadSheetPaths = lb.Items.OfType<string>().ToList();
                string ArrayofStringsPrep1 = string.Join("\",\"", ListBoxSpreadSheetPaths);
                StringBuilder lbValuebuilder = new StringBuilder(ArrayofStringsPrep1);
                string ParamValue = lbValuebuilder.Insert(0, "\"").Append("\"").ToString();

                GetCallMetricsParamsDictionary.Add(ParamName, ParamValue);
            }
            foreach (CheckBox checkbox in FilteredCheckBoxCollection)
            {
                // NOTE: This note is NOT about the below, rather it's about adding line breaks to CheckBox text.
                // In the checkbox's MainWindow.xaml control, add &#x0a; where you want the line break in the Content Property
                if (checkbox.IsChecked.HasValue) //check for a value since it can be true, false, or null
                {
                    if ((bool)checkbox.IsChecked)
                    {
                        StringBuilder checkboxbuilder = new StringBuilder(checkbox.Name);
                        var ParamNamePrep1 = checkboxbuilder.Replace("xaml", "");
                        string ParamName = checkboxbuilder.Replace("CheckBox", "").ToString();
                        string ParamValue = "";
                        GetCallMetricsParamsDictionary.Add(ParamName, ParamValue);
                    }
                }
            }

            // Attach GetCallMetricsParamsDictionary to FormControls.FormCotnrolDictionary static property so that
            // it can be accessed by ALL threads
            FormControls.FormControlDictionary = GetCallMetricsParamsDictionary;

            // TEMP: Write GetCallMetricsParamsDictionary to Output for diagnosis
            foreach (var kvp in GetCallMetricsParamsDictionary)
            {
                Console.WriteLine("{0}, {1}", kvp.Key, kvp.Value);
            }

            return GetCallMetricsParamsDictionary;
            
            ////// END Getting Form Controls //////
        }

        // Create/Config Background Worker for the Progress Bar
        public async Task ConfigAndStartPBarBGW()
        {
            // Make sure that this method runs asynchronously immediately
            await Task.Yield();

            // Define the properties that we are going to feed to out BackgroundWorkerObj class
            // BEGIN Defining the "BackgroundWorker bgw" Parameter //
            BackgroundWorker PBarWorker = new BackgroundWorker();
            PBarWorker.WorkerReportsProgress = true;
            PBarWorker.WorkerSupportsCancellation = true;
            PBarWorker.DoWork += IncrementCounterPBar;
            PBarWorker.ProgressChanged += worker_ProgressChangePBar;
            // END Defining the "BackgroundWorker bgw" Parameter //

            // BEGIN Defining the "BAutoResetEvent reset" Parameter //
            AutoResetEvent PBarBGWResetEvent = new AutoResetEvent(false);
            // END Defining the "AutoResetEvent reset" Parameter //

            // BEGIN Defining the "int val" Parameter //
            int StartingPBarValue = 0;
            // END Defining the "int val" Parameter //

            // Create a new object (i.e. new instance of the BackgroundWorkerObj class) by feeding all of the
            // params to the BackgroundWorkerObjClass constructor that takes them
            BackgroundWorkerObj PBarBackgroundWorkerObj = new BackgroundWorkerObj(PBarWorker, PBarBGWResetEvent, StartingPBarValue);

            // Start the Background Worker
            PBarBackgroundWorkerObj.worker.RunWorkerAsync();

            // Flag the Background Worker to be Cancelled. NOTE: Cancellation won't actually kick in until
            // the Background Worker job sends resetEvent.Set() to the PBarBackgroundWorkerObj.resetEvent Handler
            // as per the IncrementCounter method
            PBarBackgroundWorkerObj.worker.CancelAsync();
            //BackgroundWorkerObj.resetEvent.WaitOne(); // will block until _resetEvent.Set() call made
            PBarBackgroundWorkerObj.worker = null;
        }

        // Create/Config Background Worker for the PowerShell Function
        public async Task ConfigAndStartPSFuncBGW()
        {
            // Make sure that this method runs asynchronously immediately
            await Task.Yield();

            // Define the properties that we are going to feed to out BackgroundWorkerObj class
            // BEGIN Defining the "BackgroundWorker bgw" Parameter //
            BackgroundWorker PSFuncWorker = new BackgroundWorker();
            PSFuncWorker.WorkerReportsProgress = true;
            PSFuncWorker.WorkerSupportsCancellation = true;
            PSFuncWorker.DoWork += RunPowerShellFunction;
            PSFuncWorker.ProgressChanged += worker_ProgressChangePBar;
            // END Defining the "BackgroundWorker bgw" Parameter //

            // BEGIN Defining the "BAutoResetEvent reset" Parameter //
            AutoResetEvent PSFuncBGWResetEvent = new AutoResetEvent(false);
            // END Defining the "AutoResetEvent reset" Parameter //

            // BEGIN Defining the "int val" Parameter //
            int StartingPSFuncValue = 0;
            // END Defining the "int val" Parameter //

            // Create a new object (i.e. new instance of the BackgroundWorkerObj class) by feeding all of the
            // params to the BackgroundWorkerObjClass constructor that takes them
            BackgroundWorkerObj PSFuncBackgroundWorkerObj = new BackgroundWorkerObj(PSFuncWorker, PSFuncBGWResetEvent, StartingPSFuncValue);

            // Start the Background Worker
            PSFuncBackgroundWorkerObj.worker.RunWorkerAsync();

            // Flag the Background Worker to be Cancelled. NOTE: Cancellation won't actually kick in until
            // the Background Worker job sends resetEvent.Set() to the PBarBackgroundWorkerObj.resetEvent Handler
            // as per the IncrementCounter method
            PSFuncBackgroundWorkerObj.worker.CancelAsync();
            // BackgroundWorkerObj.resetEvent.WaitOne(); // will block until _resetEvent.Set() call made
            PSFuncBackgroundWorkerObj.worker = null;
        }

        public void RunPowerShellFunction(object sender, DoWorkEventArgs e)
        {
            // Convert the file that has the Get-CallMetrics.ps1 function to a string
            string GetCallMetricsFuncPath = Environment.CurrentDirectory + "\\Get-CallMetrics.ps1";
            // byte[] bytes = System.IO.File.ReadAllBytes(GetCallMetricsFuncPath);
            // string GetCallMetricsFuncText = System.Text.Encoding.UTF8.GetString(bytes);

            // Setup Get-CallMetrics Function parameter string
            List<string> GetCallMetricsParamStringList = new List<string>();
            foreach (var pair in FormControls.FormControlDictionary)
            {
                var ParamName = pair.Key;
                var ParamValue = pair.Value;
                string AllowedChars = @"[\w\W]";
                if (Regex.IsMatch(ParamValue, AllowedChars))
                {
                    var FunctionString = "-" + ParamName + " " + ParamValue;
                    GetCallMetricsParamStringList.Add(FunctionString);
                }
                else
                {
                    var FunctionString = "-" + ParamName;
                    GetCallMetricsParamStringList.Add(FunctionString);
                }
                
            }
            string FinalGetCallMetricsParamString = string.Join(" ", GetCallMetricsParamStringList);
            string RunFunctionWithParamsString = "Set-ExecutionPolicy -Scope Currentuser -ExecutionPolicy Bypass -Force; . " + GetCallMetricsFuncPath + "; Get-CallMetrics " + FinalGetCallMetricsParamString;

            var cmd = new System.Diagnostics.Process();
            cmd.StartInfo.FileName = "powershell.exe";
            cmd.StartInfo.RedirectStandardInput = true;
            cmd.StartInfo.RedirectStandardOutput = true;
            cmd.StartInfo.CreateNoWindow = true;
            cmd.StartInfo.UseShellExecute = false;
            cmd.Start();

            cmd.StandardInput.WriteLine(RunFunctionWithParamsString);
            cmd.StandardInput.Flush();
            cmd.StandardInput.Close();
            cmd.WaitForExit();

            (sender as BackgroundWorker).ReportProgress(100);

            // END Pass Form Control Inputs to Get-CallMetrics Function //

            //////////// END Pass Form Control Inputs to Get-CallMetrics Function ////////////

            //////// BEGIN ARCHIVE ////////
            // Alternate Method Passing Form Control Inputs to Get-CallMetrics Function //
            /*
            // First Get the File Path of PowerShell's Main DLL, i.e. System.Management.Automation
            var cmd = new System.Diagnostics.Process();
            cmd.StartInfo.FileName = "powershell.exe";
            cmd.StartInfo.RedirectStandardInput = true;
            cmd.StartInfo.RedirectStandardOutput = true;
            cmd.StartInfo.CreateNoWindow = true;
            cmd.StartInfo.UseShellExecute = false;
            cmd.Start();

            cmd.StandardInput.WriteLine("[PSObject].Assembly.Location");
            cmd.StandardInput.Flush();
            cmd.StandardInput.Close();
            cmd.WaitForExit();
            string PSdllFilePath = cmd.StandardOutput.ReadToEnd();

            // Load PowerShell's Main DLL System.Management.Automation
            var PowerShellDLL = System.Reflection.Assembly.LoadFrom(PSdllFilePath);

            using (var powershell = System.Management.Automation.PowerShell.Create())
            {
                powershell.AddScript(GetCallMetricsFuncText, false);

                powershell.Invoke();

                powershell.Commands.Clear();

                // Setup System.Collections.Generic.List so that you can add to it using its Add method
                List<string> GetCallMetricsParams = new List<string>();
                GetCallMetricsParams.Add("ExcelSpreadSheetPaths");
                GetCallMetricsParams.Add("ReportDirectory");
                GetCallMetricsParams.Add("TimeSpanStartHour");
                GetCallMetricsParams.Add("TimeSpanEndHour");
                GetCallMetricsParams.Add("Hour");
                GetCallMetricsParams.Add("Minute");
                GetCallMetricsParams.Add("Second");
                GetCallMetricsParams.Add("CalendarDay");
                GetCallMetricsParams.Add("DayOfWeek");
                GetCallMetricsParams.Add("CallType");
                GetCallMetricsParams.Add("Duration");
                GetCallMetricsParams.Add("FromWildCard");
                GetCallMetricsParams.Add("FromPhoneNumber");
                GetCallMetricsParams.Add("FromExt");
                GetCallMetricsParams.Add("FromName");
                GetCallMetricsParams.Add("ToWildCard");
                GetCallMetricsParams.Add("ToPhoneNumber");
                GetCallMetricsParams.Add("ToExt");
                GetCallMetricsParams.Add("ToName");
                GetCallMetricsParams.Add("FixSpreadSheet");
                GetCallMetricsParams.Add("ReportType");

                var GetCallMetricsFunc = powershell.AddCommand("Get-CallMetrics")

                // Sample foreach Loop
                // foreach (string arbitrarythingname in GetCallMetricsParams)
                // {
                //     Console.WriteLine(arbitrarythingname);
                // }

                powershell.AddCommand("Get-CallMetrics").AddParameter("param1", 42).AddParameter("param2", "foo");

                var results = powershell.Invoke();
            }
            */
        }

        public static void IncrementCounterPBar(object sender, DoWorkEventArgs e)
        {
            int counter = 0;
            // NOTE: The below pct has to be a decimal; as oppposed to integer if we want to do division
            // Division of two integers results in 0. See: http://stackoverflow.com/questions/9288904/division-returns-zero
            decimal pct = 0;
            while (pct < 100)
            {
                counter++;
                decimal SpreadsheetCount = FormControls.FormControlDictionary.Count;
                decimal TimeToWait = 150m * SpreadsheetCount;
                pct = (counter / TimeToWait) * 100m;
                // Convert Decimal to int to be used by ReportProgress()
                int rptpct = (int)pct;
                (sender as BackgroundWorker).ReportProgress(rptpct);
                Thread.Sleep(500);
            }
            // BackgroundWorkerObj.resetEvent.Set(); // signal that worker is done
        }

        public void worker_ProgressChangePBar(object sender, ProgressChangedEventArgs e)
        {
            int ProgressbarValue = e.ProgressPercentage;
            if (xamlProgressBar1.Value > 0 && xamlProgressBar1.Value < 20)
            {
                xamlPBarStatusLabel.Content = "Status: Fixing SpreadSheet Data...";
            }
            // TODO: Need to add additional check that FixSpreadsheet checkbox = true
            if (xamlProgressBar1.Value > 20 && xamlProgressBar1.Value < 40)
            {
                xamlPBarStatusLabel.Content = "Status: Exporting Fixed SpreadSheet To ReportDirectory...";
            }
            if (xamlProgressBar1.Value > 40 && xamlProgressBar1.Value < 60)
            {
                xamlPBarStatusLabel.Content = "Status: Filtering Data For Report Generation...";
            }
            if ((xamlProgressBar1.Value > 60 && xamlProgressBar1.Value < 100) || xamlProgressBar1.Value == 100)
            {
                xamlPBarStatusLabel.Content = "Status: Generating Report...";
            }
            if (xamlProgressBar1.Value < 100)
            {
                xamlProgressBar1.Value = ProgressbarValue;
            }
        }

        public async Task StartBackgroundTasks()
        {
            Console.WriteLine("Starting PBarGBW and PSFuncBGW");

            System.Threading.Tasks.Task task1 = ConfigAndStartPBarBGW();
            System.Threading.Tasks.Task task2 = ConfigAndStartPSFuncBGW();

            await Task.WhenAny(task1, task2);
            // await Task.WhenAll(task1, task2);
        }

        public void xamlBrowseButton_Click(object sender, RoutedEventArgs e)
        {
            // IMPORTANT NOTE: In the below function that creates a new FolderBrowserDialog, the keyword "var" makes
            // these statements functionally equivalent:
            //      System.Windows.Forms.FolderBrowserDialog dialog = new System.Windows.Forms.FolderBrowserDialog()
            //      var dialog = new System.Windows.Forms.FolderBrowserDialog()
            // What is happening is that "var" is using the fact that we're clearly instantiating a new instance of the
            // Class System.Windows.Forms.FolderBrowserDialog to "strongly type" the local variable "dialog" as 
            // System.Windows.Forms.FolderBrowserDialog, without having to type the whole thing out.
            using (System.Windows.Forms.FolderBrowserDialog dialog = new System.Windows.Forms.FolderBrowserDialog())
            {
                // NOTE: In the below file path string pathWithEnv, if you want to specify other subdirectories
                // such as Downloads or Documents, you need to EITHER double-up on backslashes (i.e. 
                // "%USERPROFILE%\\Downloads" OR preface the double-quotes with the "@" symbol
                var pathWithEnv = "%USERPROFILE%";
                var dirPath = Environment.ExpandEnvironmentVariables(pathWithEnv);
                // dialog.RootFolder = Environment.SpecialFolder.Desktop;
                dialog.SelectedPath = dirPath;
                dialog.ShowNewFolderButton = false;
                dialog.Description = "Please Choose a Directory";
                System.Windows.Forms.DialogResult result = dialog.ShowDialog();
                xamlReportDirectoryTextBox.Text = dialog.SelectedPath;
            }
        }

        // BEGIN SpreadSheet ListBox Drag-and-Drop Functionality //

        public void xamlExcelSpreadSheetPathsListBox_DragEnter(object sender, DragEventArgs e)
        {
            if (e.Data.GetDataPresent(DataFormats.FileDrop)) e.Effects = DragDropEffects.Copy;
        }

        public void xamlExcelSpreadSheetPathsListBox_Drop(object sender, DragEventArgs e)
        {
            string[] files = (string[])e.Data.GetData(DataFormats.FileDrop);
            foreach (string file in files)
                xamlExcelSpreadSheetPathsListBox.Items.Add(file);
        }

        // END SpreadSheet ListBox Drag-and-Drop Functionality //


        // The below FindVisualChildren Method Gets ALL Form Controls no matter how deep. For use, 
        // see comments in the GetFormControls method below.
        // From: http://stackoverflow.com/questions/974598/find-all-controls-in-wpf-window-by-type
        /*
        public static IEnumerable<T> FindVisualChildren<T>(DependencyObject depObj) where T : DependencyObject
        {
            if (depObj != null)
            {
                for (int i = 0; i < VisualTreeHelper.GetChildrenCount(depObj); i++)
                {
                    DependencyObject child = VisualTreeHelper.GetChild(depObj, i);
                    if (child != null && child is T)
                    {
                        yield return (T)child;
                    }

                    foreach (T childOfChild in FindVisualChildren<T>(child))
                    {
                        yield return childOfChild;
                    }
                }
            }
        }
        */

        public void xamlOKButton_Click(object sender, RoutedEventArgs e)
        {
            GetAllFormControls();
            StartBackgroundTasks();

            //// Alternate Method to the above (which uses System.Threading.Tasks.Task) is using BackGround worker ////
            // See: http://stackoverflow.com/questions/22084969/backgroundworker-wpf-difficulties-with-progress-bar/22085142#22085142
        }

        private void xamlCancelButton_Click(object sender, RoutedEventArgs e)
        {
            Environment.Exit(0);
        }
    }
}

