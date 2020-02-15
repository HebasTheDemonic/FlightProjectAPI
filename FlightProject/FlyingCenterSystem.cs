using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Threading;
using FlightProject.DAOs;
using FlightProject.POCOs;
using FlightProject.Facades;
using System.Configuration;

namespace FlightProject
{
    public class FlyingCenterSystem
    {
        static AutoResetEvent resetEvent = new AutoResetEvent(true);

        private static FlyingCenterSystem instance;
        private static object key = new object();
        public static List<AnonymousUserFacade> FacadeList;
        private static int FacadeListIndex = 0;
        public bool isTestMode = false;

        public static FlyingCenterSystem GetInstance()
        {
            lock (key)
            {
                if (instance == null)
                {
                    instance = new FlyingCenterSystem();
                }
            }
            return instance;
        }

        private FlyingCenterSystem()
        {
            FacadeList = new List<AnonymousUserFacade>();
            GetFacade();
            new Thread(FlightCleanerTimer).Start();
            new Thread(CleanFlightList).Start();
        }

        private static void FlightCleanerTimer()
        {
            Int32.TryParse(ConfigurationManager.AppSettings["HOUR_VALUE"], out int hours);
            Int32.TryParse(ConfigurationManager.AppSettings["MINUTE_VALUE"], out int minutes);
            Int32.TryParse(ConfigurationManager.AppSettings["SECOND_VALUE"], out int seconds);
            TimeSpan timeSpan = new TimeSpan(hours, minutes, seconds);
            while (true)
            {
                Thread.Sleep(timeSpan);
                resetEvent.Set();
            }

        }

        private static void CleanFlightList()
        {
            resetEvent.WaitOne();
            HiddenFacade hiddenFacade = new HiddenFacade();
            hiddenFacade.CleanFlightList();
        }

        public int UserLogin(string username, string password)
        {
            LoginService loginService = new LoginService(username, password);
            return loginService.FacadeIndex;
        }

        internal static int GetFacade(LoginToken<Administrator> loginToken)
        {
            LoggedInAdministratorFacade loggedInAdministratorFacade = new LoggedInAdministratorFacade(loginToken);
            FacadeList.Add(loggedInAdministratorFacade);
            FacadeListIndex++;
            return FacadeListIndex;
        }

        internal static int GetFacade(LoginToken<AirlineCompany> loginToken)
        {
            LoggedInAirlineFacade loggedInAirlineFacade = new LoggedInAirlineFacade(loginToken);
            FacadeList.Add(loggedInAirlineFacade);
            FacadeListIndex++;
            return FacadeListIndex;
        }

        internal static int GetFacade(LoginToken<Customer> loginToken)
        {
            LoggedInCustomerFacade loggedInCustomerFacade = new LoggedInCustomerFacade(loginToken);
            FacadeList.Add(loggedInCustomerFacade);
            FacadeListIndex++;
            return FacadeListIndex;
        }

        internal static void GetFacade()
        {
            AnonymousUserFacade anonymousUserFacade = new AnonymousUserFacade();
            FacadeList.Add(anonymousUserFacade);
        }

        public void StartTest()
        {
            if (isTestMode)
            {
                HiddenFacade hiddenFacade = new HiddenFacade();
                hiddenFacade.DbTestPrep();
            }
        }

        public void ClearDb()
        {
            HiddenFacade hiddenFacade = new HiddenFacade();
            hiddenFacade.clearDb();
        }
    }


}
