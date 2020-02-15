using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using FlightProject.DAOs;

namespace FlightProject.Facades
{
    class HiddenFacade
    {
        GeneralDAO generalDAO;

        internal HiddenFacade()
        {
            generalDAO = new GeneralDAO();
        }

        public void clearDb()
        {
            generalDAO.DBClear();
        }

        public void DbTestPrep()
        {
            generalDAO.DBTestPrep();
        }

        public void CleanFlightList()
        {
            generalDAO.CleanFlightList();
        }
    }
}
